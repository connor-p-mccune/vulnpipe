"""Pipeline orchestrator: run every stage in order and produce the CI verdict.

Drives the full pipeline -- intake -> nmap scan -> zap scan -> enrich -> dedup ->
false-positive filter -> prioritize -> diff vs baseline -> gate -- and returns the
prioritized findings together with the baseline :class:`~vulnpipe.ci.differ.Diff`
and the :class:`~vulnpipe.ci.gate.GateResult`. Rendering and persisting reports is
left to the CLI; this module produces the data and the verdict.

Authorization is enforced here as well as in the CLI (defense in depth): the run
refuses to start unless the caller acknowledges authorization *and* every target
falls inside the scope allowlist.

Concurrency. The network layer scales through Nmap's native range handling -- a
single invocation covers a 200+ host range -- so it needs no application-level
fan-out. The heavier web layer is fanned out across a **bounded thread pool**
(``run.max_workers``) with ZAP active-scan concurrency **capped separately**
(``zap.max_concurrency``) via a semaphore, because active scans are resource
intensive. The web layer scans both URLs declared in config and HTTP/HTTPS
services discovered by the Nmap stage (in scope only). A third, passive
supply-chain layer analyzes any configured CycloneDX SBOMs against OSV.dev; its
findings join the network/web findings before enrichment.

Scanners are resolved through :mod:`vulnpipe.scanners.registry` by name, never
special-cased; injectable scan callables keep the pipeline testable without real
tools. Deterministic for fixed scanner output: stages preserve order where it
matters and prioritization imposes a stable final ordering.
"""

import logging
import threading
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import vulnpipe.scanners  # noqa: F401  (import for scanner registration side effect)
from vulnpipe.ci.baseline import Baseline
from vulnpipe.ci.differ import Diff, diff_findings
from vulnpipe.ci.gate import DEFAULT_GATE_SEVERITY, GateResult, evaluate_gate
from vulnpipe.core.config import (
    Config,
    Scope,
    Target,
    ensure_authorized,
    ensure_config_in_scope,
    url_in_scope,
)
from vulnpipe.core.logging import get_logger, log_event
from vulnpipe.core.models import Finding, Severity
from vulnpipe.enrichment import EnrichmentClients, build_enrichment, enrich_findings
from vulnpipe.enrichment._http import open_cache
from vulnpipe.processing import (
    FalsePositiveConfig,
    deduplicate,
    filter_false_positives,
    prioritize,
)
from vulnpipe.sbom.analyzer import analyze_sbom
from vulnpipe.sbom.cyclonedx import SbomError, load_sbom
from vulnpipe.sbom.osv_client import OsvClient
from vulnpipe.scanners.nmap_scanner import SOURCE as NMAP_SOURCE
from vulnpipe.scanners.registry import get_scanner
from vulnpipe.scanners.zap_scanner import SOURCE as ZAP_SOURCE
from vulnpipe.scanners.zap_scanner import WebTarget, select_web_targets_with_auth

_log = get_logger(__name__)

#: Injectable scan callables (default to the registered scanners) so the pipeline
#: can be exercised without real Nmap/ZAP/OSV.
NetworkScan = Callable[[Config], list[Finding]]
WebScan = Callable[[Config, Sequence[str]], list[Finding]]
SbomScan = Callable[[Config], list[Finding]]

# Service-name hints (substring match) marking an Nmap-discovered web service, and
# the well-known web ports used as a fallback when the service is unidentified.
_WEB_SERVICE_HINTS = ("http", "www")
_HTTPS_HINTS = ("https", "ssl")
_WEB_PORTS = frozenset({80, 443, 8000, 8008, 8080, 8443, 8888})
_HTTPS_PORTS = frozenset({443, 8443})


@dataclass(frozen=True)
class PipelineResult:
    """The output of a pipeline run: prioritized findings plus the CI verdict."""

    findings: tuple[Finding, ...]
    diff: Diff
    gate: GateResult


# --------------------------------------------------------------------------- #
# Web-service discovery from the network layer
# --------------------------------------------------------------------------- #
def _is_web_finding(finding: Finding) -> bool:
    """Whether an Nmap finding denotes an HTTP/HTTPS service worth handing to ZAP.

    A recognized service name is trusted (so a non-web service on a web port is not
    scanned); when Nmap could not identify the service, a well-known web port is
    used as the fallback signal.
    """
    if finding.port is None:
        return False
    service = str(finding.metadata.get("service") or "").strip().lower()
    if service:
        return any(hint in service for hint in _WEB_SERVICE_HINTS)
    return finding.port in _WEB_PORTS


def _scheme_for(finding: Finding) -> str:
    """Choose ``http`` or ``https`` for a discovered web service."""
    service = str(finding.metadata.get("service") or "").lower()
    if any(hint in service for hint in _HTTPS_HINTS) or finding.port in _HTTPS_PORTS:
        return "https"
    return "http"


def derive_web_targets(findings: Iterable[Finding], scope: Scope) -> list[str]:
    """Derive in-scope web URLs from Nmap-discovered HTTP/HTTPS services.

    Produces one ``scheme://host:port`` URL per distinct discovered web service,
    de-duplicated in first-seen order and filtered to the scope allowlist (a
    discovered service on an in-scope host is in scope, but the check is explicit
    defense in depth). Non-Nmap findings are ignored.
    """
    urls: dict[str, None] = {}
    for finding in findings:
        if finding.source != NMAP_SOURCE or not _is_web_finding(finding):
            continue
        url = f"{_scheme_for(finding)}://{finding.host}:{finding.port}"
        if url not in urls and url_in_scope(url, scope):
            urls[url] = None
    return list(urls)


def _collect_web_targets(config: Config, discovered_urls: Sequence[str]) -> list[WebTarget]:
    """Combine declared (authenticated) web targets with discovered ones.

    Declared targets come first and win on duplicate URLs, so a discovered URL that
    matches a declared one keeps the declared target's auth. Discovered URLs are
    added without auth. Every URL is scope-checked.
    """
    targets: list[WebTarget] = []
    seen: set[str] = set()
    for target in select_web_targets_with_auth(config):
        targets.append(target)
        seen.add(target.url)
    for url in discovered_urls:
        if url in seen or not url_in_scope(url, config.scope):
            continue
        seen.add(url)
        targets.append(WebTarget(url=url, auth=None))
    return targets


# --------------------------------------------------------------------------- #
# Default scan stages (registry-resolved scanners)
# --------------------------------------------------------------------------- #
def _default_network_scan(config: Config) -> list[Finding]:
    """Run the registered network scanner over the in-scope range."""
    scanner = get_scanner(NMAP_SOURCE)(config)
    return scanner.scan()


def _single_web_config(config: Config, target: WebTarget) -> Config:
    """A copy of ``config`` whose only target is ``target`` (URL + its auth)."""
    return config.model_copy(update={"targets": [Target(urls=[target.url], auth=target.auth)]})


def _default_web_scan(config: Config, discovered_urls: Sequence[str]) -> list[Finding]:
    """Scan declared + discovered web targets with a bounded, ZAP-capped pool.

    Each target is scanned by the registered web scanner over a config narrowed to
    that single URL. The thread pool is bounded by ``run.max_workers``; a semaphore
    caps how many ZAP active scans run at once at ``zap.max_concurrency``.
    """
    if not config.zap.enabled:
        return []
    targets = _collect_web_targets(config, discovered_urls)
    if not targets:
        log_event(_log, logging.INFO, "no in-scope web targets; skipping web layer")
        return []

    scanner_cls = get_scanner(ZAP_SOURCE)
    cap = max(1, config.zap.max_concurrency)
    workers = max(1, min(config.run.max_workers, len(targets)))
    semaphore = threading.Semaphore(cap)

    def scan_one(target: WebTarget) -> list[Finding]:
        with semaphore:
            return scanner_cls(_single_web_config(config, target)).scan()

    log_event(
        _log,
        logging.INFO,
        "web layer scanning",
        targets=len(targets),
        workers=workers,
        zap_cap=cap,
    )
    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="vulnpipe-web") as pool:
        for result in pool.map(scan_one, targets):
            findings.extend(result)
    return findings


# --------------------------------------------------------------------------- #
# Supply-chain (SBOM) layer
# --------------------------------------------------------------------------- #
def _default_sbom_scan(config: Config) -> list[Finding]:
    """Analyze every configured CycloneDX SBOM against OSV.dev.

    SBOM paths are local artifacts, so they bypass the host/URL scope allowlist. A
    file that cannot be read or parsed degrades to a logged warning and is skipped,
    consistent with a failed scanner host, rather than aborting the run. The OSV
    client shares the enrichment on-disk cache.
    """
    if not config.sbom:
        return []
    cache = open_cache(config.enrichment.cache_dir)
    client = OsvClient(cache=cache)
    findings: list[Finding] = []
    try:
        for path in config.sbom:
            try:
                sbom = load_sbom(path)
            except SbomError as exc:
                log_event(
                    _log, logging.WARNING, "sbom load failed; skipping", path=path, error=str(exc)
                )
                continue
            findings.extend(analyze_sbom(sbom, client))
    finally:
        client.close()
    return findings


# --------------------------------------------------------------------------- #
# Enrichment
# --------------------------------------------------------------------------- #
def _enrich(
    config: Config, findings: list[Finding], clients: EnrichmentClients | None
) -> list[Finding]:
    """Enrich findings via the given clients, building (and closing) them if needed."""
    if not findings:
        return findings
    owns = clients is None
    active = clients if clients is not None else build_enrichment(config)
    try:
        return enrich_findings(findings, nvd=active.nvd, epss=active.epss, kev=active.kev)
    finally:
        if owns:
            active.close()


# --------------------------------------------------------------------------- #
# The pipeline
# --------------------------------------------------------------------------- #
def run_pipeline(
    config: Config,
    *,
    authorized: bool = False,
    allowlist: FalsePositiveConfig | None = None,
    baseline: Baseline | None = None,
    gate_threshold: Severity = DEFAULT_GATE_SEVERITY,
    gate_min_risk_score: int | None = None,
    enrichment: EnrichmentClients | None = None,
    run_network: NetworkScan | None = None,
    run_web: WebScan | None = None,
    run_sbom: SbomScan | None = None,
) -> PipelineResult:
    """Run the full pipeline and return prioritized findings plus the CI verdict.

    Enforces authorization and scope before scanning. ``run_network`` / ``run_web``
    / ``run_sbom`` default to the registered Nmap / ZAP scanners and the OSV-backed
    SBOM analyzer but can be injected (e.g. in tests). The SBOM layer analyzes any
    ``config.sbom`` files and contributes findings that flow through enrichment,
    dedup, filtering, and prioritization like scanner output. ``baseline`` drives
    the diff/gate -- when omitted, every finding counts as new (an empty baseline).
    Raises :class:`~vulnpipe.core.config.AuthorizationError` /
    :class:`~vulnpipe.core.config.OutOfScopeError` if the run is not authorized or a
    target is out of scope.
    """
    ensure_authorized(authorized=authorized, scope=config.scope)
    ensure_config_in_scope(config)

    network_scan = run_network if run_network is not None else _default_network_scan
    web_scan = run_web if run_web is not None else _default_web_scan
    sbom_scan = run_sbom if run_sbom is not None else _default_sbom_scan

    network_findings = network_scan(config)
    discovered = derive_web_targets(network_findings, config.scope)
    web_findings = web_scan(config, discovered)
    sbom_findings = sbom_scan(config)
    raw = [*network_findings, *web_findings, *sbom_findings]
    log_event(
        _log,
        logging.INFO,
        "scan stages complete",
        network=len(network_findings),
        web=len(web_findings),
        sbom=len(sbom_findings),
        discovered_web=len(discovered),
    )

    enriched = _enrich(config, raw, enrichment)
    deduped = deduplicate(enriched)
    filtered = filter_false_positives(deduped, allowlist or FalsePositiveConfig())
    prioritized = prioritize(filtered, criticality=config.prioritization.criticality_for)

    effective_baseline = baseline if baseline is not None else Baseline()
    diff = diff_findings(prioritized, effective_baseline)
    gate = evaluate_gate(diff, threshold=gate_threshold, min_risk_score=gate_min_risk_score)
    log_event(
        _log,
        logging.INFO,
        "pipeline complete",
        findings=len(prioritized),
        new=len(diff.new),
        persisting=len(diff.persisting),
        resolved=len(diff.resolved),
        gate="pass" if gate.passed else "fail",
    )
    return PipelineResult(findings=tuple(prioritized), diff=diff, gate=gate)


__all__ = [
    "NetworkScan",
    "PipelineResult",
    "SbomScan",
    "WebScan",
    "derive_web_targets",
    "run_pipeline",
]
