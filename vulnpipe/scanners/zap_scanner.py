"""OWASP ZAP scanner integration (web layer).

This module drives a **running ZAP daemon** over its API (``from zapv2 import
ZAPv2``) and turns its alerts into normalized
:class:`~vulnpipe.core.models.Finding` objects. ZAP runs as a separate
process/container; this module only drives ZAP's spider + active scan -- it never
launches exploits. Like the nmap integration it is split into small, pure pieces
so the mapping logic can be unit-tested without ever talking to ZAP:

* :func:`select_web_targets` resolves the in-scope web URLs from the
  configuration, enforcing the scope allowlist *before* any scan runs.
* :func:`alert_to_finding` / :func:`normalize_alerts` map a ZAP ``core.alerts``
  payload onto findings: ZAP risk -> :class:`~vulnpipe.core.models.Severity`,
  ZAP confidence -> :class:`~vulnpipe.core.models.Confidence`, CWE references,
  and any CVE ids ZAP cites (handed to enrichment downstream).
* :class:`ZapScanner` ties them together: per URL it selects/creates a context,
  spiders, waits, active-scans, polls ``ascan.status`` to 100, then pulls
  ``core.alerts`` -- all with bounded timeouts, degrading failures to logged
  warnings while retaining partial results.

Detection and reporting only: a finding carries ZAP's *evidence* (the proof an
issue exists) plus its location (URL, parameter, method) for remediation, but it
does **not** carry ZAP's raw ``attack`` input vector -- this tool reports issues,
it does not replicate attack payloads. Severity is taken from ZAP's risk rating;
the CVSS score is left unknown (``None``) for the enrichment stage to fill rather
than being fabricated here. CVE ids are accepted only when they match the
canonical pattern (via the shared normalizer).
"""

import logging
import re
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from zapv2 import ZAPv2

from vulnpipe.auth.auth_contexts import apply_auth_context, build_auth_context
from vulnpipe.core.config import (
    AuthConfig,
    Config,
    OutOfScopeError,
    Scope,
    ZapConfig,
    resolve_secret,
    url_in_scope,
)
from vulnpipe.core.logging import get_logger, log_event
from vulnpipe.core.models import Confidence, Finding, Severity
from vulnpipe.processing.normalizer import clean_cves, make_finding
from vulnpipe.scanners.base import BaseScanner
from vulnpipe.scanners.registry import register

_log = get_logger(__name__)

#: ``Finding.source`` and registry key for this scanner.
SOURCE = "zap"

#: Seconds between status polls while waiting on the spider / active scan.
_POLL_INTERVAL_SECONDS = 2.0

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# ZAP risk -> Severity. ZAP has no "critical" band, so its ratings map onto the
# first four severities; CVSS-derived criticality (if any) is added in enrichment.
_RISK_TO_SEVERITY: dict[str, Severity] = {
    "informational": Severity.INFORMATIONAL,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
}
_RISKCODE_TO_SEVERITY: dict[str, Severity] = {
    "0": Severity.INFORMATIONAL,
    "1": Severity.LOW,
    "2": Severity.MEDIUM,
    "3": Severity.HIGH,
}

# ZAP confidence -> Confidence. ZAP reports either a label or a numeric code
# (0=False Positive .. 4=User Confirmed); both forms are accepted.
_CONFIDENCE_TO_LEVEL: dict[str, Confidence] = {
    "false positive": Confidence.FALSE_POSITIVE,
    "low": Confidence.LOW,
    "medium": Confidence.MEDIUM,
    "high": Confidence.HIGH,
    "confirmed": Confidence.CONFIRMED,
    "user confirmed": Confidence.CONFIRMED,
}
_CONFIDENCE_CODE_TO_LEVEL: dict[str, Confidence] = {
    "0": Confidence.FALSE_POSITIVE,
    "1": Confidence.LOW,
    "2": Confidence.MEDIUM,
    "3": Confidence.HIGH,
    "4": Confidence.CONFIRMED,
}

_SCHEME_DEFAULT_PORT: dict[str, int] = {"http": 80, "https": 443}


# --------------------------------------------------------------------------- #
# Target selection
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class WebTarget:
    """An in-scope web URL together with the auth config it should be scanned under."""

    url: str
    auth: AuthConfig | None = None


def select_web_targets_with_auth(config: Config) -> list[WebTarget]:
    """Return the de-duplicated, in-scope web targets (URL + auth) to hand to ZAP.

    Only the ``urls`` of each :class:`~vulnpipe.core.config.Target` are web targets;
    host-only (network) targets belong to the nmap stage and are ignored here. Each
    URL carries its target's ``auth`` block so the scanner can authenticate. URLs are
    de-duplicated keeping the first occurrence (and its auth). Enforces the
    authorization scope as a hard rule: a configured URL outside the allowlist raises
    :class:`~vulnpipe.core.config.OutOfScopeError` and no scan is attempted.
    """
    selected: list[WebTarget] = []
    seen: set[str] = set()
    for target in config.targets:
        for url in target.urls:
            if not url_in_scope(url, config.scope):
                raise OutOfScopeError(
                    f"Web target {url!r} is not within the configured scope allowlist"
                )
            if url not in seen:
                seen.add(url)
                selected.append(WebTarget(url=url, auth=target.auth))
    return selected


def select_web_targets(config: Config) -> list[str]:
    """Return the de-duplicated, in-scope web URLs to hand to ZAP.

    A thin view over :func:`select_web_targets_with_auth` for callers that only need
    the URLs (the same scope enforcement and de-duplication apply).
    """
    return [target.url for target in select_web_targets_with_auth(config)]


# --------------------------------------------------------------------------- #
# Small value helpers
# --------------------------------------------------------------------------- #
def _str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _clean_meta(meta: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in meta.items() if value is not None}


def _parse_percent(value: Any) -> int:
    """Parse a ZAP status percentage (``"100"`` etc.); unparseable -> ``0``."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def _severity_from_risk(alert: Mapping[str, Any]) -> Severity:
    """Map a ZAP alert's risk rating onto a :class:`Severity`.

    Prefers the human ``risk`` label, falling back to the numeric ``riskcode``.
    An unrecognized rating degrades to ``INFORMATIONAL`` -- never guessed upward.
    """
    risk = _str(alert.get("risk"))
    if risk is not None:
        mapped = _RISK_TO_SEVERITY.get(risk.lower())
        if mapped is not None:
            return mapped
    code = _str(alert.get("riskcode"))
    if code is not None:
        mapped = _RISKCODE_TO_SEVERITY.get(code)
        if mapped is not None:
            return mapped
    return Severity.INFORMATIONAL


def _confidence_from_zap(value: Any) -> Confidence | None:
    """Map a ZAP confidence (label or numeric code) onto a :class:`Confidence`.

    Returns ``None`` for missing/unknown values so the false-positive filter can
    apply its own default rather than inheriting a guessed level.
    """
    text = _str(value)
    if text is None:
        return None
    mapped = _CONFIDENCE_TO_LEVEL.get(text.lower())
    if mapped is not None:
        return mapped
    return _CONFIDENCE_CODE_TO_LEVEL.get(text)


def _clean_cwe(value: Any) -> str | None:
    """Return a canonical ``CWE-<n>`` id, or ``None``.

    ZAP uses ``-1`` (and occasionally ``0``) to mean "no CWE"; those and any
    non-numeric value yield ``None`` so the finding's ``cwe_ids`` stays honest.
    """
    text = _str(value)
    if text is None:
        return None
    try:
        number = int(text)
    except ValueError:
        return None
    return f"CWE-{number}" if number > 0 else None


def _split_references(reference: Any) -> list[str]:
    """Split a ZAP ``reference`` blob (newline-separated URLs) into entries.

    De-duplication and trimming are handled by :func:`make_finding`; this only
    breaks the blob into individual non-empty lines.
    """
    if not isinstance(reference, str):
        return []
    return [line.strip() for line in reference.splitlines() if line.strip()]


def _harvest_cves(alert: Mapping[str, Any]) -> tuple[str, ...]:
    """Collect any CVE ids ZAP cites for an alert, validated and de-duplicated.

    Looks at an explicit ``cveid`` field, the keys/values of the ``tags`` map
    (newer ZAP rules tag findings with CVE ids), and free-text in ``reference``.
    Only canonical ``CVE-YYYY-NNNN`` ids survive :func:`clean_cves`; non-CVE tags
    (e.g. ``OWASP_2021_A06``) are dropped rather than coerced.
    """
    tokens: list[str] = []
    explicit = alert.get("cveid")
    if isinstance(explicit, str):
        tokens.append(explicit)
    tags = alert.get("tags")
    if isinstance(tags, Mapping):
        for key, value in tags.items():
            if isinstance(key, str):
                tokens.append(key)
            if isinstance(value, str):
                tokens.extend(_CVE_RE.findall(value))
    reference = alert.get("reference")
    if isinstance(reference, str):
        tokens.extend(_CVE_RE.findall(reference))
    return clean_cves(tokens)


def _alert_host_port(url: str | None) -> tuple[str | None, int | None]:
    """Extract ``(host, port)`` from an alert URL.

    The port is taken from the URL if present, otherwise defaulted from the
    scheme (``https`` -> 443, ``http`` -> 80). Returns ``(None, None)`` when the
    URL is missing or has no host.
    """
    if not url:
        return None, None
    parsed = urlparse(url)
    host = parsed.hostname
    if host is None:
        return None, None
    port = parsed.port
    if port is None:
        port = _SCHEME_DEFAULT_PORT.get(parsed.scheme)
    return host, port


# --------------------------------------------------------------------------- #
# Finding construction
# --------------------------------------------------------------------------- #
def alert_to_finding(alert: Mapping[str, Any], *, scope: Scope | None = None) -> Finding | None:
    """Map a single ZAP alert onto a :class:`Finding`, or ``None`` if unusable.

    Returns ``None`` for an alert with no URL/host or no title (it cannot be
    fingerprinted), and -- when ``scope`` is supplied -- for any URL outside the
    allowlist (defense in depth; targets are already scope-checked before the
    scan). The raw ``attack`` payload is intentionally not carried.
    """
    url = _str(alert.get("url"))
    host, port = _alert_host_port(url)
    if host is None:
        log_event(
            _log,
            logging.WARNING,
            "zap alert missing url; skipping",
            alert=_str(alert.get("name")),
        )
        return None
    if scope is not None and url is not None and not url_in_scope(url, scope):
        log_event(_log, logging.WARNING, "zap skipping out-of-scope alert", url=url)
        return None
    title = _str(alert.get("name")) or _str(alert.get("alert"))
    if title is None:
        log_event(_log, logging.WARNING, "zap alert missing title; skipping", url=url)
        return None
    cwe = _clean_cwe(alert.get("cweid"))
    metadata: dict[str, Any] = {
        "url": url,
        "method": _str(alert.get("method")),
        "param": _str(alert.get("param")),
        "alert_ref": _str(alert.get("alertRef")),
        "wasc_id": _str(alert.get("wascid")),
        "input_vector": _str(alert.get("inputVector")),
        "other_info": _str(alert.get("otherinfo")),
    }
    return make_finding(
        source=SOURCE,
        host=host,
        title=title,
        severity=_severity_from_risk(alert),
        port=port,
        protocol="tcp" if port is not None else None,
        plugin_id=_str(alert.get("pluginId")),
        confidence=_confidence_from_zap(alert.get("confidence")),
        description=_str(alert.get("description")),
        solution=_str(alert.get("solution")),
        evidence=_str(alert.get("evidence")),
        references=_split_references(alert.get("reference")),
        cve_ids=_harvest_cves(alert),
        cwe_ids=(cwe,) if cwe is not None else (),
        metadata=_clean_meta(metadata),
    )


def _sort_key(finding: Finding) -> tuple[str, int, str, str, str, str]:
    return (
        finding.host,
        finding.port if finding.port is not None else -1,
        finding.plugin_id or "",
        finding.title,
        str(finding.metadata.get("url") or ""),
        str(finding.metadata.get("param") or ""),
    )


def normalize_alerts(
    alerts: Iterable[Mapping[str, Any]], *, scope: Scope | None = None
) -> list[Finding]:
    """Normalize a ZAP ``core.alerts`` payload into findings, ordered deterministically.

    Each alert becomes at most one finding (unusable/out-of-scope alerts are
    dropped). Output is sorted by host, port, plugin id, title, URL and parameter
    so report output and the differ are stable across runs for fixed input.
    """
    findings: list[Finding] = []
    for alert in alerts:
        finding = alert_to_finding(alert, scope=scope)
        if finding is not None:
            findings.append(finding)
    findings.sort(key=_sort_key)
    return findings


# --------------------------------------------------------------------------- #
# ZAP client driving
# --------------------------------------------------------------------------- #
def _build_client(config: ZapConfig, api_key: str | None) -> ZAPv2:
    """Build a ZAP API client pointed at the configured daemon.

    The ZAP daemon doubles as the proxy the client talks through; the API key (if
    any) resolves from the environment, never from the config file.
    """
    proxies = {"http": config.api_url, "https": config.api_url}
    return ZAPv2(apikey=api_key, proxies=proxies)


def _subtree_regex(url: str) -> str:
    """A ZAP context include-regex matching ``url`` and everything beneath it."""
    return re.escape(url.rstrip("/")) + ".*"


def _poll_until_complete(poll_fn: Callable[[], Any], *, timeout: float, label: str) -> bool:
    """Poll ``poll_fn`` (a ZAP ``*.status`` call) until it reports 100% or times out.

    Returns ``True`` on completion and ``False`` on timeout (a warning is logged
    and the caller proceeds with whatever partial results ZAP has gathered).
    """
    deadline = time.monotonic() + timeout
    while True:
        if _parse_percent(poll_fn()) >= 100:
            return True
        if time.monotonic() >= deadline:
            log_event(_log, logging.WARNING, f"zap {label} timed out", timeout=timeout)
            return False
        time.sleep(_POLL_INTERVAL_SECONDS)


@dataclass(frozen=True)
class _ScanContext:
    """The ZAP context (and authenticated user, if any) a URL is scanned under.

    ``user_id`` is set only for credentialed auth schemes; when present the spider
    and active scan run *as that user* so they stay authenticated.
    """

    name: str | None
    context_id: str | None
    user_id: str | None


@register
class ZapScanner(BaseScanner):
    """Drive a running ZAP daemon over in-scope web URLs and return findings.

    Failures degrade to logged warnings rather than crashing the pipeline: a
    daemon that cannot be reached, or a spider/active-scan/alert call that fails
    for one URL, yields an empty (or partial) finding list so a single bad target
    never aborts the run.

    When a target defines an ``auth`` block, the context is configured for
    authenticated scanning (see :mod:`vulnpipe.auth.auth_contexts`); an auth setup
    failure degrades to a logged warning and an unauthenticated scan rather than
    skipping the target.
    """

    name = SOURCE

    def scan(self) -> list[Finding]:
        cfg = self.config.zap
        if not cfg.enabled:
            log_event(_log, logging.INFO, "zap scanner disabled; skipping")
            return []
        targets = select_web_targets_with_auth(self.config)
        if not targets:
            log_event(_log, logging.INFO, "zap has no in-scope web targets; skipping")
            return []
        api_key = resolve_secret(cfg.api_key_env, required=False)
        try:
            client = _build_client(cfg, api_key)
        except Exception as exc:  # daemon unreachable / bad proxy -> no scan, not a crash
            log_event(_log, logging.WARNING, "zap client init failed", error=str(exc))
            return []
        raw_alerts: list[dict[str, Any]] = []
        failed = 0
        for target in targets:
            try:
                raw_alerts.extend(self._scan_url(client, target, cfg))
            except Exception as exc:  # one bad URL must not abort the whole run
                failed += 1
                log_event(
                    _log, logging.WARNING, "zap scan failed for url", url=target.url, error=str(exc)
                )
        findings = normalize_alerts(raw_alerts, scope=self.config.scope)
        log_event(
            _log,
            logging.INFO,
            "zap scan complete",
            findings=len(findings),
            targets=len(targets),
            failed=failed,
        )
        return findings

    def _scan_url(self, client: ZAPv2, target: WebTarget, cfg: ZapConfig) -> list[dict[str, Any]]:
        """Run the full spider -> active-scan -> collect flow for one web target."""
        log_event(_log, logging.INFO, "zap scanning url", url=target.url)
        context = self._ensure_context(client, target)
        self._run_spider(client, target.url, context, cfg)
        self._run_active_scan(client, target.url, context, cfg)
        return self._collect_alerts(client, target.url)

    def _ensure_context(self, client: ZAPv2, target: WebTarget) -> _ScanContext:
        """Create a ZAP context for ``target``'s subtree, configuring auth if defined.

        Returns an empty context (no name/id) if context creation fails, so the
        scan still proceeds unauthenticated against the URL.
        """
        host = urlparse(target.url).hostname or "web"
        name = f"vulnpipe-{host}"
        try:
            context_id = str(client.context.new_context(name))
            client.context.include_in_context(name, _subtree_regex(target.url))
        except Exception as exc:
            log_event(
                _log, logging.DEBUG, "zap context setup skipped", url=target.url, error=str(exc)
            )
            return _ScanContext(name=None, context_id=None, user_id=None)
        user_id = self._configure_auth(client, context_id, target)
        return _ScanContext(name=name, context_id=context_id, user_id=user_id)

    def _configure_auth(self, client: ZAPv2, context_id: str, target: WebTarget) -> str | None:
        """Apply the target's auth context to ``context_id``; ``None`` if unauthenticated.

        A missing credential or any auth-setup failure degrades to a logged warning
        and an unauthenticated scan rather than aborting the target.
        """
        if target.auth is None:
            return None
        try:
            plan = build_auth_context(target.auth)
            user_id = apply_auth_context(client, context_id, plan)
            log_event(
                _log,
                logging.INFO,
                "zap authenticated context configured",
                url=target.url,
                auth=plan.kind,
            )
            return user_id
        except Exception as exc:
            log_event(
                _log,
                logging.WARNING,
                "zap auth setup failed; scanning unauthenticated",
                url=target.url,
                error=str(exc),
            )
            return None

    def _run_spider(self, client: ZAPv2, url: str, context: _ScanContext, cfg: ZapConfig) -> None:
        """Spider ``url`` and wait, bounded by ``spider_max_duration_minutes``."""
        if cfg.spider_max_duration_minutes <= 0:
            log_event(_log, logging.INFO, "zap spider disabled; skipping", url=url)
            return
        if context.user_id is not None and context.context_id is not None:
            scan_id = client.spider.scan_as_user(context.context_id, context.user_id, url)
        else:
            scan_id = client.spider.scan(url, contextname=context.name)
        timeout = cfg.spider_max_duration_minutes * 60
        _poll_until_complete(lambda: client.spider.status(scan_id), timeout=timeout, label="spider")

    def _run_active_scan(
        self, client: ZAPv2, url: str, context: _ScanContext, cfg: ZapConfig
    ) -> None:
        """Active-scan ``url`` and poll to completion, bounded by the config timeout."""
        if context.user_id is not None and context.context_id is not None:
            scan_id = client.ascan.scan_as_user(url, context.context_id, context.user_id, True)
        else:
            scan_id = client.ascan.scan(url)
        _poll_until_complete(
            lambda: client.ascan.status(scan_id),
            timeout=cfg.active_scan_timeout_seconds,
            label="active scan",
        )

    def _collect_alerts(self, client: ZAPv2, url: str) -> list[dict[str, Any]]:
        """Pull ``core.alerts`` for ``url`` as a list of plain alert dicts."""
        raw = client.core.alerts(baseurl=url)
        alerts: list[dict[str, Any]] = []
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict):
                    alerts.append(item)
        return alerts


__all__ = [
    "SOURCE",
    "WebTarget",
    "ZapScanner",
    "alert_to_finding",
    "normalize_alerts",
    "select_web_targets",
    "select_web_targets_with_auth",
]
