"""Nmap scanner integration (network layer).

This module drives the ``nmap`` binary and turns its XML output into normalized
:class:`~vulnpipe.core.models.Finding` objects. It is split into small, pure
pieces so the parsing logic can be unit-tested without ever running nmap:

* :func:`select_network_targets` resolves the in-scope network targets from the
  configuration, enforcing the scope allowlist *before* any scan runs.
* :func:`build_nmap_command` assembles the argument list (always a list, never a
  shell string) used to invoke ``nmap``.
* :func:`parse_nmap_xml` parses ``nmap -oX`` output into findings: one
  informational finding per open service plus one vulnerability finding per CVE
  emitted by the ``vulners`` / ``vuln`` NSE scripts.
* :class:`NmapScanner` ties them together, runs the subprocess with bounded
  timeouts, and degrades scanner failures to logged warnings.

Subprocess calls always pass an argument list -- never ``shell=True`` with
interpolated target input. CVE ids and CVSS scores are taken verbatim from the
scanner output; nothing is fabricated, and a missing/invalid score becomes
``None`` (unknown) rather than a guess.
"""

import logging
import re
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from libnmap.parser import NmapParser

from vulnpipe.core.config import Config, OutOfScopeError, host_in_scope
from vulnpipe.core.logging import get_logger, log_event
from vulnpipe.core.models import Confidence, Finding, Severity
from vulnpipe.processing.normalizer import make_finding, normalize_cve, parse_cvss
from vulnpipe.scanners.base import BaseScanner
from vulnpipe.scanners.registry import register

_log = get_logger(__name__)

#: ``Finding.source`` and registry key for this scanner.
SOURCE = "nmap"

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# Command construction & target selection
# --------------------------------------------------------------------------- #
def select_network_targets(config: Config) -> list[str]:
    """Return the de-duplicated, in-scope network targets to hand to ``nmap``.

    Only :class:`~vulnpipe.core.config.Target` entries with a ``host`` (an IP,
    CIDR, or hostname) are network targets; URL-only targets belong to the web
    (ZAP) stage and are ignored here. Enforces the authorization scope as a hard
    rule: a configured host outside the allowlist raises
    :class:`~vulnpipe.core.config.OutOfScopeError` and no scan is attempted.
    """
    selected: list[str] = []
    seen: set[str] = set()
    for target in config.targets:
        if target.host is None:
            continue
        if not host_in_scope(target.host, config.scope.hosts):
            raise OutOfScopeError(
                f"Network target {target.host!r} is not within the configured scope allowlist"
            )
        if target.host not in seen:
            seen.add(target.host)
            selected.append(target.host)
    return selected


def build_nmap_command(config: Config, targets: Sequence[str]) -> list[str]:
    """Build the ``nmap`` argument list for ``targets``.

    Emits XML to stdout (``-oX -``) and enables service/version detection
    (``-sV``) so product/version data is available for both reporting and the
    vulners CPE matching. Timing, port selection, and NSE scripts come from
    :class:`~vulnpipe.core.config.NmapConfig`. Targets are passed as discrete
    arguments (nmap handles CIDR ranges and host lists natively); nothing is
    ever interpolated into a shell string.
    """
    cfg = config.nmap
    command = [cfg.binary, "-oX", "-", "-sV", f"-T{cfg.timing_template}"]
    if cfg.ports:
        command += ["-p", cfg.ports]
    elif cfg.top_ports is not None:
        command += ["--top-ports", str(cfg.top_ports)]
    if cfg.scripts:
        command += ["--script", ",".join(cfg.scripts)]
    command += list(cfg.extra_args)
    command += list(targets)
    return command


# --------------------------------------------------------------------------- #
# Small value helpers
# --------------------------------------------------------------------------- #
def _str_or_none(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _parse_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"true", "yes", "1"}:
        return True
    if text in {"false", "no", "0"}:
        return False
    return None


def _confidence_from_conf(conf: Any) -> Confidence | None:
    """Map nmap's service-detection confidence (0-10) onto a Confidence level."""
    if conf is None:
        return None
    try:
        level = int(conf)
    except (TypeError, ValueError):
        return None
    if level >= 9:
        return Confidence.CONFIRMED
    if level >= 7:
        return Confidence.HIGH
    if level >= 4:
        return Confidence.MEDIUM
    if level >= 1:
        return Confidence.LOW
    return None


def _service_summary(name: str | None, product: str | None, version: str | None) -> str | None:
    label = " ".join(part for part in (product, version) if part)
    if name and label:
        return f"{name} ({label})"
    return name or label or None


def _clean_meta(meta: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in meta.items() if value is not None}


def _first_hostname(host: Any) -> str | None:
    for name in getattr(host, "hostnames", None) or []:
        text = _str_or_none(name)
        if text is not None:
            return text
    return None


def _os_guess(host: Any) -> tuple[str | None, int | None]:
    matches = host.os_match_probabilities() or []
    if not matches:
        return None, None
    best = max(matches, key=lambda match: (int(match.accuracy), str(match.name)))
    return str(best.name), int(best.accuracy)


# --------------------------------------------------------------------------- #
# CVE harvesting from NSE script output
# --------------------------------------------------------------------------- #
@dataclass
class _CveHit:
    """A CVE reference harvested from a script result, with optional context."""

    cve: str
    cvss: float | None = None
    is_exploit: bool | None = None
    title: str | None = None
    state: str | None = None


def _merge_hit(hits: dict[str, _CveHit], hit: _CveHit) -> None:
    """Record ``hit``, filling in any fields a previous sighting left unknown."""
    existing = hits.get(hit.cve)
    if existing is None:
        hits[hit.cve] = hit
        return
    if existing.cvss is None:
        existing.cvss = hit.cvss
    if existing.is_exploit is None:
        existing.is_exploit = hit.is_exploit
    if existing.title is None:
        existing.title = hit.title
    if existing.state is None:
        existing.state = hit.state


def _harvest_cves(node: Any, hits: dict[str, _CveHit] | None = None) -> dict[str, _CveHit]:
    """Recursively collect CVE references from a parsed NSE ``elements`` structure.

    Handles both shapes nmap/libnmap produce: ``vulners`` rows where the CVE is an
    ``id`` element alongside a ``cvss`` value, and ``vuln``-category tables where
    the CVE is itself a table key whose value carries ``state``/``title``. Keying
    by CVE id collapses the awkward unnamed-table nesting libnmap emits.
    """
    if hits is None:
        hits = {}
    if isinstance(node, dict):
        ident = node.get("id")
        if isinstance(ident, str):
            cve = normalize_cve(ident)
            if cve is not None:
                _merge_hit(
                    hits,
                    _CveHit(
                        cve=cve,
                        cvss=parse_cvss(node.get("cvss")),
                        is_exploit=_parse_bool(node.get("is_exploit")),
                        title=_str_or_none(node.get("title")),
                        state=_str_or_none(node.get("state")),
                    ),
                )
        for key, value in node.items():
            if isinstance(key, str):
                keyed = normalize_cve(key)
                if keyed is not None:
                    child = value if isinstance(value, dict) else {}
                    _merge_hit(
                        hits,
                        _CveHit(
                            cve=keyed,
                            cvss=parse_cvss(child.get("cvss")),
                            is_exploit=_parse_bool(child.get("is_exploit")),
                            title=_str_or_none(child.get("title")),
                            state=_str_or_none(child.get("state")),
                        ),
                    )
            _harvest_cves(value, hits)
    elif isinstance(node, list):
        for item in node:
            _harvest_cves(item, hits)
    return hits


def _harvest_from_text(text: Any, hits: dict[str, _CveHit]) -> None:
    """Backfill CVE ids mentioned only in a script's free-text output."""
    if not isinstance(text, str):
        return
    for raw in _CVE_RE.findall(text):
        cve = normalize_cve(raw)
        if cve is not None and cve not in hits:
            hits[cve] = _CveHit(cve=cve)


def _cve_confidence(hit: _CveHit) -> Confidence:
    """Reflect the detection method: actively confirmed > CVSS-scored > bare id."""
    if hit.state is not None and hit.state.upper().startswith("VULNERABLE"):
        return Confidence.HIGH
    if hit.cvss is not None:
        return Confidence.MEDIUM
    return Confidence.LOW


def _cve_description(script_id: str, cve: str, summary: str | None) -> str:
    target = summary or "the detected service"
    return f"{cve} reported by the Nmap {script_id} script for {target}."


# --------------------------------------------------------------------------- #
# Finding construction
# --------------------------------------------------------------------------- #
def _cve_findings(
    host: str,
    port: int | None,
    protocol: str | None,
    script: Any,
    summary: str | None,
    base_meta: dict[str, Any],
) -> list[Finding]:
    """Turn one NSE script result into one finding per distinct CVE."""
    script_id = _str_or_none(script.get("id")) or "nse"
    hits = _harvest_cves(script.get("elements"))
    _harvest_from_text(script.get("output"), hits)
    findings: list[Finding] = []
    for cve in sorted(hits):
        hit = hits[cve]
        metadata = _clean_meta(
            {
                **base_meta,
                "nmap_script": script_id,
                "is_exploit": hit.is_exploit,
                "state": hit.state,
            }
        )
        findings.append(
            make_finding(
                source=SOURCE,
                host=host,
                title=cve,
                port=port,
                protocol=protocol,
                plugin_id=script_id,
                confidence=_cve_confidence(hit),
                description=hit.title or _cve_description(script_id, cve, summary),
                cve_ids=(cve,),
                cvss_score=hit.cvss,
                metadata=metadata,
            )
        )
    return findings


def _findings_for_service(
    host: str,
    hostname: str | None,
    os_name: str | None,
    os_accuracy: int | None,
    service: Any,
) -> list[Finding]:
    """Build the open-service inventory finding plus any per-service CVE findings."""
    sd = service.service_dict or {}
    port = int(service.port)
    protocol = str(service.protocol)
    name = _str_or_none(sd.get("name")) or _str_or_none(getattr(service, "service", None))
    product = _str_or_none(sd.get("product"))
    version = _str_or_none(sd.get("version"))
    cpes = [str(cpe) for cpe in (sd.get("cpelist") or [])]
    summary = _service_summary(name, product, version)
    base_meta: dict[str, Any] = {
        "hostname": hostname,
        "os": os_name,
        "os_accuracy": os_accuracy,
        "service": name,
        "product": product,
        "version": version,
        "cpe": cpes or None,
    }
    findings = [
        make_finding(
            source=SOURCE,
            host=host,
            title=f"Open port {port}/{protocol}",
            severity=Severity.INFORMATIONAL,
            port=port,
            protocol=protocol,
            confidence=_confidence_from_conf(sd.get("conf")),
            description=summary,
            metadata=_clean_meta({**base_meta, "detection_method": _str_or_none(sd.get("method"))}),
        )
    ]
    for script in service.scripts_results or []:
        findings.extend(_cve_findings(host, port, protocol, script, summary, base_meta))
    return findings


def _findings_for_host(host: Any) -> list[Finding]:
    """Build all findings for a single up host (services, CVEs, host-level scripts)."""
    address = str(host.address)
    hostname = _first_hostname(host)
    os_name, os_accuracy = _os_guess(host)
    findings: list[Finding] = []
    open_services = sorted(
        (svc for svc in host.services if str(svc.state) == "open"),
        key=lambda svc: (int(svc.port), str(svc.protocol)),
    )
    for service in open_services:
        findings.extend(_findings_for_service(address, hostname, os_name, os_accuracy, service))
    host_meta: dict[str, Any] = {"hostname": hostname, "os": os_name, "os_accuracy": os_accuracy}
    for script in host.scripts_results or []:
        findings.extend(_cve_findings(address, None, None, script, None, host_meta))
    return findings


def _parse_report(xml: str) -> Any:
    """Parse nmap XML, retrying as a partial/interrupted scan before giving up."""
    if not xml or not xml.strip():
        return None
    last_error: Exception | None = None
    for incomplete in (False, True):
        try:
            return NmapParser.parse_fromstring(xml, incomplete=incomplete)
        except Exception as exc:  # libnmap raises bare Exceptions on malformed input
            last_error = exc
    log_event(_log, logging.WARNING, "nmap XML parse failed", error=str(last_error))
    return None


def parse_nmap_xml(xml: str, *, scope_hosts: Sequence[str] | None = None) -> list[Finding]:
    """Parse ``nmap -oX`` output into normalized findings, ordered deterministically.

    Hosts are processed in address order; only hosts reported up are included. When
    ``scope_hosts`` is given, any host outside the allowlist is dropped with a
    warning (defense in depth -- targets are already scope-checked before the scan).
    """
    report = _parse_report(xml)
    if report is None:
        return []
    findings: list[Finding] = []
    for host in sorted(report.hosts, key=lambda h: str(h.address)):
        if not host.is_up():
            continue
        address = str(host.address)
        if scope_hosts is not None and not host_in_scope(address, scope_hosts):
            log_event(_log, logging.WARNING, "nmap skipping out-of-scope host", host=address)
            continue
        findings.extend(_findings_for_host(host))
    return findings


# --------------------------------------------------------------------------- #
# Subprocess helpers
# --------------------------------------------------------------------------- #
def _decode(raw: Any) -> str | None:
    if isinstance(raw, bytes):
        text = raw.decode("utf-8", "replace")
    elif isinstance(raw, str):
        text = raw
    else:
        return None
    return text or None


def _truncate(text: str | None, limit: int = 500) -> str | None:
    if text is None:
        return None
    collapsed = " ".join(text.split())
    if not collapsed:
        return None
    return collapsed if len(collapsed) <= limit else collapsed[:limit] + "..."


@register
class NmapScanner(BaseScanner):
    """Drive ``nmap`` over the in-scope network range and return normalized findings.

    Failures degrade to logged warnings rather than crashing the pipeline: a
    missing binary, a non-zero exit, a timeout, or unparseable output all yield an
    empty (or partial) finding list so a single bad host never aborts the run.
    """

    name = SOURCE

    def scan(self) -> list[Finding]:
        cfg = self.config.nmap
        if not cfg.enabled:
            log_event(_log, logging.INFO, "nmap scanner disabled; skipping")
            return []
        targets = select_network_targets(self.config)
        if not targets:
            log_event(_log, logging.INFO, "nmap has no in-scope network targets; skipping")
            return []
        command = build_nmap_command(self.config, targets)
        xml, partial = self._run(command, cfg.timeout_seconds)
        if xml is None:
            return []
        findings = parse_nmap_xml(xml, scope_hosts=self.config.scope.hosts)
        log_event(
            _log,
            logging.INFO,
            "nmap scan complete",
            findings=len(findings),
            partial=partial,
            targets=len(targets),
        )
        return findings

    def _run(self, command: Sequence[str], timeout: int) -> tuple[str | None, bool]:
        """Run nmap, returning ``(xml_or_none, timed_out)`` and never raising."""
        log_event(_log, logging.INFO, "running nmap", command=" ".join(command))
        try:
            proc = subprocess.run(
                list(command),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError:
            log_event(_log, logging.WARNING, "nmap binary not found", binary=command[0])
            return None, False
        except subprocess.TimeoutExpired as exc:
            log_event(_log, logging.WARNING, "nmap scan timed out", timeout=timeout)
            return _decode(exc.stdout), True  # best-effort partial XML
        if proc.returncode != 0:
            log_event(
                _log,
                logging.WARNING,
                "nmap exited non-zero",
                code=proc.returncode,
                stderr=_truncate(proc.stderr),
            )
        return (proc.stdout or None), False


__all__ = [
    "SOURCE",
    "NmapScanner",
    "build_nmap_command",
    "parse_nmap_xml",
    "select_network_targets",
]
