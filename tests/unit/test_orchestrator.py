"""Unit tests for the pipeline orchestrator.

Covers web-service discovery from the network layer, the full pipeline wiring with
injected stub scanners (no real Nmap/ZAP, no network), authorization/scope
enforcement, baseline diffing and gating, and the bounded web pool with its ZAP
concurrency cap.
"""

import threading
from collections.abc import Sequence
from pathlib import Path

import pytest

from vulnpipe.core import orchestrator
from vulnpipe.core.config import (
    AuthorizationError,
    Config,
    OutOfScopeError,
    RunConfig,
    Scope,
    Target,
    ZapConfig,
)
from vulnpipe.core.models import Finding, Severity
from vulnpipe.processing import FalsePositiveConfig
from vulnpipe.processing.false_positive import PluginRule
from vulnpipe.processing.normalizer import make_finding
from vulnpipe.scanners.base import BaseScanner

SCOPE = Scope(hosts=["10.0.0.0/24", "*.lab.example.com"], urls=["https://app.lab.example.com"])


def _config(targets: list[Target] | None = None, **overrides: object) -> Config:
    return Config(
        scope=SCOPE,
        targets=targets or [Target(host="10.0.0.10", urls=["https://app.lab.example.com"])],
        **overrides,  # type: ignore[arg-type]
    )


def _open_port(host: str, port: int, service: str | None) -> Finding:
    return make_finding(
        source="nmap",
        host=host,
        title=f"Open port {port}/tcp",
        severity=Severity.INFORMATIONAL,
        port=port,
        metadata={"service": service} if service is not None else {},
    )


# --------------------------------------------------------------------------- #
# Web-service discovery
# --------------------------------------------------------------------------- #
def test_derive_web_targets_picks_http_and_https() -> None:
    findings = [
        _open_port("10.0.0.10", 80, "http"),
        _open_port("10.0.0.10", 443, "https"),
    ]
    assert orchestrator.derive_web_targets(findings, SCOPE) == [
        "http://10.0.0.10:80",
        "https://10.0.0.10:443",
    ]


def test_derive_web_targets_uses_https_for_443_named_http() -> None:
    # Nmap often labels TLS-wrapped HTTP as "http" on 443; the port forces https.
    findings = [_open_port("10.0.0.10", 443, "http")]
    assert orchestrator.derive_web_targets(findings, SCOPE) == ["https://10.0.0.10:443"]


def test_derive_web_targets_trusts_known_non_web_service_on_web_port() -> None:
    # A recognized non-web service on a web port is not handed to ZAP.
    findings = [_open_port("10.0.0.10", 8080, "ssh")]
    assert orchestrator.derive_web_targets(findings, SCOPE) == []


def test_derive_web_targets_falls_back_to_port_for_unknown_service() -> None:
    findings = [_open_port("10.0.0.10", 8443, None), _open_port("10.0.0.10", 22, None)]
    assert orchestrator.derive_web_targets(findings, SCOPE) == ["https://10.0.0.10:8443"]


def test_derive_web_targets_dedupes_and_skips_non_nmap() -> None:
    zap_finding = make_finding(source="zap", host="10.0.0.10", title="x", port=443)
    findings = [
        _open_port("10.0.0.10", 443, "https"),
        _open_port("10.0.0.10", 443, "https"),  # duplicate
        zap_finding,  # non-nmap, ignored
    ]
    assert orchestrator.derive_web_targets(findings, SCOPE) == ["https://10.0.0.10:443"]


def test_derive_web_targets_filters_out_of_scope_host() -> None:
    findings = [_open_port("203.0.113.5", 443, "https")]  # not in SCOPE
    assert orchestrator.derive_web_targets(findings, SCOPE) == []


def test_derive_web_targets_skips_portless_findings() -> None:
    portless = make_finding(source="nmap", host="10.0.0.10", title="CVE-2021-1", plugin_id="vuln")
    assert orchestrator.derive_web_targets([portless], SCOPE) == []


# --------------------------------------------------------------------------- #
# Web-target collection and the default scan stages
# --------------------------------------------------------------------------- #
def test_collect_web_targets_declared_wins_over_discovered() -> None:
    cfg = Config(
        scope=SCOPE,
        targets=[Target(urls=["https://app.lab.example.com"])],
    )
    # The declared URL also appears as discovered; the declared target (with its
    # auth slot) wins, and a genuinely new discovered URL is appended.
    collected = orchestrator._collect_web_targets(
        cfg, ["https://app.lab.example.com", "https://10.0.0.10:443"]
    )
    assert [t.url for t in collected] == [
        "https://app.lab.example.com",
        "https://10.0.0.10:443",
    ]


def test_default_network_scan_uses_registered_scanner(monkeypatch: pytest.MonkeyPatch) -> None:
    canned = [_open_port("10.0.0.10", 443, "https")]

    class _FakeNmap(BaseScanner):
        name = "nmap"

        def scan(self) -> list[Finding]:
            return canned

    monkeypatch.setattr(orchestrator, "get_scanner", lambda _name: _FakeNmap)
    assert orchestrator._default_network_scan(_config()) == canned


def test_default_web_scan_no_targets_returns_empty() -> None:
    cfg = Config(scope=Scope(hosts=["10.0.0.0/24"]), targets=[Target(host="10.0.0.10")])
    assert orchestrator._default_web_scan(cfg, []) == []


def test_enrich_empty_findings_short_circuits() -> None:
    assert orchestrator._enrich(_config(), [], orchestrator.EnrichmentClients()) == []


def test_enrich_builds_and_closes_clients(monkeypatch: pytest.MonkeyPatch) -> None:
    class _SpyClients:
        def __init__(self) -> None:
            self.nvd = None
            self.epss = None
            self.kev = None
            self.closed = False

        def close(self) -> None:
            self.closed = True

    spy = _SpyClients()
    monkeypatch.setattr(orchestrator, "build_enrichment", lambda _cfg: spy)
    finding = make_finding(source="nmap", host="10.0.0.10", title="no-cve", plugin_id="p")
    # clients=None -> the orchestrator builds them and must close what it owns.
    result = orchestrator._enrich(_config(), [finding], None)
    assert result == [finding]  # no CVEs -> enrichment is a no-op
    assert spy.closed is True


# --------------------------------------------------------------------------- #
# run_pipeline wiring with injected stub scanners
# --------------------------------------------------------------------------- #
def _nmap_findings() -> list[Finding]:
    return [
        _open_port("10.0.0.10", 443, "https"),
        make_finding(
            source="nmap",
            host="10.0.0.10",
            title="CVE-2021-44228",
            severity=Severity.CRITICAL,
            port=443,
            plugin_id="vulners",
            cve_ids=["CVE-2021-44228"],
            cvss_score=10.0,
        ),
    ]


def _zap_findings(host: str = "app.lab.example.com") -> list[Finding]:
    return [
        make_finding(
            source="zap",
            host=host,
            title="Cross Site Scripting (Reflected)",
            severity=Severity.HIGH,
            port=443,
            plugin_id="40012",
        )
    ]


def test_run_pipeline_wires_all_stages() -> None:
    captured: dict[str, Sequence[str]] = {}

    def run_web(config: Config, discovered: Sequence[str]) -> list[Finding]:
        captured["discovered"] = list(discovered)
        return _zap_findings()

    result = orchestrator.run_pipeline(
        _config(),
        authorized=True,
        enrichment=orchestrator.EnrichmentClients(),  # no NVD/EPSS -> no network
        run_network=lambda _c: _nmap_findings(),
        run_web=run_web,
    )
    # The web stage was fed the URL discovered from the Nmap https service.
    assert captured["discovered"] == ["https://10.0.0.10:443"]
    titles = [f.title for f in result.findings]
    assert "CVE-2021-44228" in titles
    assert "Cross Site Scripting (Reflected)" in titles
    # Prioritized: the Critical CVE outranks the High XSS.
    assert result.findings[0].title == "CVE-2021-44228"


def _sbom_finding() -> list[Finding]:
    return [
        make_finding(
            source="sbom",
            host="acme-webapp",
            title="GHSA-x84v-xcm2-53pg: requests 2.19.0",
            severity=Severity.HIGH,
            plugin_id="GHSA-x84v-xcm2-53pg",
            cve_ids=["CVE-2018-18074"],
            cvss_score=7.5,
        )
    ]


def test_run_pipeline_includes_injected_sbom_layer() -> None:
    captured: dict[str, bool] = {}

    def run_sbom(config: Config) -> list[Finding]:
        captured["called"] = True
        return _sbom_finding()

    result = orchestrator.run_pipeline(
        _config(),
        authorized=True,
        enrichment=orchestrator.EnrichmentClients(),
        run_network=lambda _c: _nmap_findings(),
        run_web=lambda _c, _u: _zap_findings(),
        run_sbom=run_sbom,
    )
    assert captured["called"] is True
    titles = [f.title for f in result.findings]
    # Supply-chain findings flow through the same dedup/prioritize path as scanners.
    assert "GHSA-x84v-xcm2-53pg: requests 2.19.0" in titles
    assert any(f.source == "sbom" for f in result.findings)


def test_default_sbom_scan_empty_when_unconfigured() -> None:
    # No sbom paths in config -> the default layer does no work and no OSV client.
    assert orchestrator._default_sbom_scan(_config()) == []


def test_default_sbom_scan_skips_unreadable_files(tmp_path: Path) -> None:
    missing = tmp_path / "nope.json"
    cfg = _config(sbom=[str(missing)])
    # A missing/invalid SBOM degrades to a warning and an empty result, not a crash.
    assert orchestrator._default_sbom_scan(cfg) == []


def test_run_pipeline_requires_authorization() -> None:
    with pytest.raises(AuthorizationError):
        orchestrator.run_pipeline(
            _config(),
            authorized=False,
            run_network=lambda _c: [],
            run_web=lambda _c, _u: [],
        )


def test_run_pipeline_refuses_out_of_scope_target() -> None:
    cfg = Config(scope=SCOPE, targets=[Target(host="203.0.113.0/24")])  # outside scope
    with pytest.raises(OutOfScopeError):
        orchestrator.run_pipeline(
            cfg,
            authorized=True,
            run_network=lambda _c: [],
            run_web=lambda _c, _u: [],
        )


def test_run_pipeline_gate_fails_on_new_high() -> None:
    result = orchestrator.run_pipeline(
        _config(),
        authorized=True,
        enrichment=orchestrator.EnrichmentClients(),
        run_network=lambda _c: [],
        run_web=lambda _c, _u: _zap_findings(),  # one new High finding, no baseline
    )
    assert result.gate.passed is False
    assert result.gate.exit_code == 1


def test_run_pipeline_baseline_exempts_known_findings() -> None:
    from vulnpipe.ci.baseline import build_baseline

    xss = _zap_findings()
    baseline = build_baseline(xss)
    result = orchestrator.run_pipeline(
        _config(),
        authorized=True,
        baseline=baseline,
        enrichment=orchestrator.EnrichmentClients(),
        run_network=lambda _c: [],
        run_web=lambda _c, _u: xss,  # the High is baselined -> gate passes
    )
    assert result.gate.passed is True
    assert [f.title for f in result.diff.persisting] == ["Cross Site Scripting (Reflected)"]
    assert result.diff.new == ()


def test_run_pipeline_applies_false_positive_filter() -> None:
    allowlist = FalsePositiveConfig(plugins=(PluginRule(id="40012"),))
    result = orchestrator.run_pipeline(
        _config(),
        authorized=True,
        allowlist=allowlist,
        enrichment=orchestrator.EnrichmentClients(),
        run_network=lambda _c: [],
        run_web=lambda _c, _u: _zap_findings(),  # suppressed by the allowlist
    )
    assert result.findings == ()


def test_run_pipeline_dedupes_across_scanners() -> None:
    # The same fingerprint emitted twice collapses to a single finding.
    dupe = make_finding(source="nmap", host="10.0.0.10", title="dup", port=443, plugin_id="p")
    result = orchestrator.run_pipeline(
        _config(),
        authorized=True,
        enrichment=orchestrator.EnrichmentClients(),
        run_network=lambda _c: [dupe, dupe],
        run_web=lambda _c, _u: [],
    )
    assert len(result.findings) == 1


# --------------------------------------------------------------------------- #
# Default web pool: bounded concurrency with the ZAP cap
# --------------------------------------------------------------------------- #
def _multi_url_config(*, max_concurrency: int, max_workers: int, count: int) -> Config:
    urls = [f"https://h{i}.lab.example.com" for i in range(count)]
    return Config(
        scope=Scope(hosts=["*.lab.example.com"]),
        targets=[Target(urls=[url]) for url in urls],
        zap=ZapConfig(max_concurrency=max_concurrency),
        run=RunConfig(max_workers=max_workers),
    )


def _make_capturing_scanner(
    state: dict[str, int], lock: threading.Lock, barrier: threading.Barrier
) -> type[BaseScanner]:
    class _FakeZap(BaseScanner):
        name = "zap"

        def scan(self) -> list[Finding]:
            with lock:
                state["current"] += 1
                state["max"] = max(state["max"], state["current"])
            try:
                barrier.wait()  # forces `parties` scans to overlap; times out if capped lower
            finally:
                with lock:
                    state["current"] -= 1
            url = self.config.targets[0].urls[0]
            return [make_finding(source="zap", host=url, title="finding", plugin_id="1")]

    return _FakeZap


def test_web_pool_allows_and_caps_concurrency(monkeypatch: pytest.MonkeyPatch) -> None:
    cap = 2
    state = {"current": 0, "max": 0}
    lock = threading.Lock()
    barrier = threading.Barrier(cap, timeout=5)  # exactly `cap` must overlap each cycle
    monkeypatch.setattr(
        orchestrator, "get_scanner", lambda _name: _make_capturing_scanner(state, lock, barrier)
    )
    cfg = _multi_url_config(max_concurrency=cap, max_workers=4, count=4)
    findings = orchestrator._default_web_scan(cfg, [])
    assert len(findings) == 4
    # The semaphore let concurrency reach the cap (barrier released) but never exceed it.
    assert state["max"] == cap


def test_web_pool_serializes_when_cap_is_one(monkeypatch: pytest.MonkeyPatch) -> None:
    state = {"current": 0, "max": 0}
    lock = threading.Lock()
    barrier = threading.Barrier(1)  # a single party releases immediately
    monkeypatch.setattr(
        orchestrator, "get_scanner", lambda _name: _make_capturing_scanner(state, lock, barrier)
    )
    cfg = _multi_url_config(max_concurrency=1, max_workers=4, count=3)
    findings = orchestrator._default_web_scan(cfg, [])
    assert len(findings) == 3
    assert state["max"] == 1  # ZAP concurrency stayed capped at one


def test_web_pool_skips_when_zap_disabled() -> None:
    cfg = _multi_url_config(max_concurrency=1, max_workers=2, count=2)
    cfg = cfg.model_copy(update={"zap": ZapConfig(enabled=False)})
    assert orchestrator._default_web_scan(cfg, []) == []
