"""Nuclei scanner integration (template-based detection layer).

Drives ProjectDiscovery's `nuclei <https://github.com/projectdiscovery/nuclei>`_ --
a fast, community-templated scanner -- over the in-scope web targets and turns its
JSONL output into normalized :class:`~vulnpipe.core.models.Finding` objects. It is
the third detection source alongside Nmap (network) and ZAP (web), and joins the
pipeline the same way: registered by name, injectable in the orchestrator, and
nothing downstream knows a finding came from nuclei except via ``Finding.source``.

**Detection and reporting only.** vulnpipe runs nuclei's *detection* templates
(known-CVE checks, misconfigurations, exposures, technology fingerprints) and parses
the matches. It never passes nuclei's fuzzing / DAST / interactsh-exploitation flags,
and -- like the ZAP integration -- it carries the match *location* and *evidence*
onto a finding but not a replayable attack payload. Severity is taken from the
template's own rating; CVE ids, CWE ids, and the CVSS score are read verbatim from the
template ``classification`` (a missing/invalid one becomes ``None``, never a guess).

Split into small pure pieces so the mapping is unit-tested without ever running the
binary:

* :func:`select_nuclei_targets` resolves the in-scope target URLs, enforcing the
  scope allowlist *before* any scan runs.
* :func:`build_nuclei_command` assembles the argument list (always a list, never a
  shell string).
* :func:`parse_nuclei_jsonl` / :func:`result_to_finding` map nuclei JSONL onto findings.
* :class:`NucleiScanner` runs the subprocess with a bounded timeout and degrades any
  failure to a logged warning.
"""

import json
import logging
import subprocess
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlparse

from vulnpipe.core.config import Config, OutOfScopeError, Scope, url_in_scope
from vulnpipe.core.logging import get_logger, log_event
from vulnpipe.core.models import Confidence, Finding, Severity
from vulnpipe.core.standards import parse_cwe
from vulnpipe.processing.normalizer import make_finding, parse_cvss
from vulnpipe.scanners.base import BaseScanner
from vulnpipe.scanners.registry import register

_log = get_logger(__name__)

#: ``Finding.source`` and registry key for this scanner.
SOURCE = "nuclei"

_SCHEME_PORT: dict[str, int] = {"http": 80, "https": 443}

# nuclei severity label -> normalized Severity ("unknown" degrades to informational).
_SEVERITY: dict[str, Severity] = {
    "info": Severity.INFORMATIONAL,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "unknown": Severity.INFORMATIONAL,
}


# --------------------------------------------------------------------------- #
# Target selection & command construction
# --------------------------------------------------------------------------- #
def select_nuclei_targets(config: Config) -> list[str]:
    """Return the de-duplicated, in-scope target URLs to hand to nuclei.

    Only the ``urls`` of each target are used (network-only targets belong to the
    nmap stage). Enforces the authorization scope as a hard rule: a URL outside the
    allowlist raises :class:`~vulnpipe.core.config.OutOfScopeError` and no scan runs.
    """
    selected: list[str] = []
    seen: set[str] = set()
    for target in config.targets:
        for url in target.urls:
            if not url_in_scope(url, config.scope):
                raise OutOfScopeError(
                    f"Web target {url!r} is not within the configured scope allowlist"
                )
            if url not in seen:
                seen.add(url)
                selected.append(url)
    return selected


def build_nuclei_command(config: Config, targets: Sequence[str]) -> list[str]:
    """Build the ``nuclei`` argument list for ``targets``.

    Emits JSONL (``-jsonl``) to stdout and disables the interactive banner, colour,
    and the template auto-update (so a scan is quiet and does not phone home mid-run).
    Template and severity selection come from :class:`~vulnpipe.core.config.NucleiConfig`;
    targets are passed as discrete ``-u`` arguments, never interpolated into a shell.
    """
    cfg = config.nuclei
    command = [cfg.binary, "-jsonl", "-silent", "-no-color", "-disable-update-check"]
    if cfg.severities:
        command += ["-severity", ",".join(cfg.severities)]
    for template in cfg.templates:
        command += ["-t", template]
    if cfg.rate_limit is not None:
        command += ["-rate-limit", str(cfg.rate_limit)]
    command += list(cfg.extra_args)
    for url in targets:
        command += ["-u", url]
    return command


# --------------------------------------------------------------------------- #
# Small value helpers
# --------------------------------------------------------------------------- #
def _str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _as_str_list(value: Any) -> list[str]:
    """Coerce a nuclei field that may be a list or a single string into a list."""
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    if isinstance(value, str):
        return [value]
    return []


def _clean_meta(meta: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in meta.items() if value not in (None, [], "")}


def _host_port(value: str | None) -> tuple[str | None, int | None]:
    """Extract ``(host, port)`` from a nuclei ``host`` / ``matched-at`` value.

    Handles a full URL (``https://host[:port]``) and a bare ``host[:port]``; the port
    defaults from the scheme for a URL. Returns ``(None, None)`` when unusable.
    """
    text = (value or "").strip()
    if not text:
        return None, None
    if text.startswith(("http://", "https://")):
        parsed = urlparse(text)
        if parsed.hostname is None:
            return None, None
        return parsed.hostname, parsed.port or _SCHEME_PORT.get(parsed.scheme)
    if text.count(":") == 1:
        host, _, port_text = text.partition(":")
        try:
            return (host or None), int(port_text)
        except ValueError:
            return (text or None), None
    return text, None


def _cwe_ids(value: Any) -> list[str]:
    """Normalize nuclei CWE ids (``"cwe-79"``) to the canonical ``CWE-79`` form."""
    ids: list[str] = []
    for raw in _as_str_list(value):
        number = parse_cwe(raw)
        if number is not None:
            ids.append(f"CWE-{number}")
    return ids


# --------------------------------------------------------------------------- #
# Finding construction
# --------------------------------------------------------------------------- #
def result_to_finding(result: Any, *, scope: Scope | None = None) -> Finding | None:
    """Map a single nuclei JSONL result object onto a :class:`Finding`, or ``None``.

    Returns ``None`` for a result with no resolvable host or title (it cannot be
    fingerprinted) and -- when ``scope`` is supplied -- for a matched URL outside the
    allowlist (defense in depth; targets are already scope-checked before the scan).
    """
    if not isinstance(result, dict):
        return None
    info = result.get("info")
    info = info if isinstance(info, dict) else {}

    matched = _str(result.get("matched-at")) or _str(result.get("matched_at"))
    host, port = _host_port(_str(result.get("host")) or matched)
    if host is None:
        log_event(_log, logging.WARNING, "nuclei result missing host; skipping", matched=matched)
        return None

    url = matched if matched and matched.startswith(("http://", "https://")) else None
    if scope is not None and url is not None and not url_in_scope(url, scope):
        log_event(_log, logging.WARNING, "nuclei skipping out-of-scope result", url=url)
        return None

    template_id = _str(result.get("template-id")) or _str(result.get("template_id"))
    title = _str(info.get("name")) or template_id
    if title is None:
        log_event(_log, logging.WARNING, "nuclei result missing title; skipping", host=host)
        return None

    classification = info.get("classification")
    classification = classification if isinstance(classification, dict) else {}
    severity = _SEVERITY.get((_str(info.get("severity")) or "").lower(), Severity.INFORMATIONAL)
    metadata = _clean_meta(
        {
            "nuclei_type": _str(result.get("type")),
            "matched_at": matched,
            "template_path": _str(result.get("template-path")),
            "url": url,
            "ip": _str(result.get("ip")),
            "tags": _as_str_list(info.get("tags")),
        }
    )
    return make_finding(
        source=SOURCE,
        host=host,
        title=title,
        severity=severity,
        port=port,
        protocol="tcp" if port is not None else None,
        plugin_id=template_id,
        confidence=Confidence.MEDIUM,
        description=_str(info.get("description")),
        solution=_str(info.get("remediation")),
        references=_as_str_list(info.get("reference")),
        cve_ids=_as_str_list(classification.get("cve-id")),
        cwe_ids=_cwe_ids(classification.get("cwe-id")),
        cvss_score=parse_cvss(classification.get("cvss-score")),
        cvss_vector=_str(classification.get("cvss-metrics")),
        metadata=metadata,
    )


def _sort_key(finding: Finding) -> tuple[str, int, str, str]:
    return (
        finding.host,
        finding.port if finding.port is not None else -1,
        finding.plugin_id or "",
        finding.title,
    )


def parse_nuclei_jsonl(text: str, *, scope: Scope | None = None) -> list[Finding]:
    """Parse nuclei JSONL output into findings, ordered deterministically.

    One JSON object per line; blank lines and unparseable lines are skipped with a
    warning rather than aborting. Output is sorted by host, port, template id and
    title so report output and the differ are stable across runs for fixed input.
    """
    findings: list[Finding] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            result = json.loads(stripped)
        except ValueError:
            log_event(_log, logging.WARNING, "nuclei JSONL line not valid JSON; skipping")
            continue
        finding = result_to_finding(result, scope=scope)
        if finding is not None:
            findings.append(finding)
    findings.sort(key=_sort_key)
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


@register
class NucleiScanner(BaseScanner):
    """Drive ``nuclei`` over the in-scope web targets and return normalized findings.

    Failures degrade to logged warnings rather than crashing the pipeline: a missing
    binary, a non-zero exit, a timeout, or unparseable output yields an empty (or
    partial) finding list so a bad run never aborts the pipeline.
    """

    name = SOURCE

    def scan(self) -> list[Finding]:
        cfg = self.config.nuclei
        if not cfg.enabled:
            log_event(_log, logging.INFO, "nuclei scanner disabled; skipping")
            return []
        targets = select_nuclei_targets(self.config)
        if not targets:
            log_event(_log, logging.INFO, "nuclei has no in-scope targets; skipping")
            return []
        command = build_nuclei_command(self.config, targets)
        stdout, partial = self._run(command, cfg.timeout_seconds)
        if stdout is None:
            return []
        findings = parse_nuclei_jsonl(stdout, scope=self.config.scope)
        log_event(
            _log,
            logging.INFO,
            "nuclei scan complete",
            findings=len(findings),
            partial=partial,
            targets=len(targets),
        )
        return findings

    def _run(self, command: Sequence[str], timeout: int) -> tuple[str | None, bool]:
        """Run nuclei, returning ``(jsonl_or_none, timed_out)`` and never raising."""
        log_event(_log, logging.INFO, "running nuclei", targets=len(command))
        try:
            proc = subprocess.run(
                list(command),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError:
            log_event(_log, logging.WARNING, "nuclei binary not found", binary=command[0])
            return None, False
        except subprocess.TimeoutExpired as exc:
            log_event(_log, logging.WARNING, "nuclei scan timed out", timeout=timeout)
            return _decode(exc.stdout), True  # best-effort partial output
        if proc.returncode != 0:
            log_event(_log, logging.WARNING, "nuclei exited non-zero", code=proc.returncode)
        return (proc.stdout or None), False


__all__ = [
    "SOURCE",
    "NucleiScanner",
    "build_nuclei_command",
    "parse_nuclei_jsonl",
    "result_to_finding",
    "select_nuclei_targets",
]
