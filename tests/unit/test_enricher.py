"""Unit tests for the enrichment step (clients faked; no network, no real cache)."""

from typing import Any

import pytest

from vulnpipe.core.config import Config, EnrichmentConfig, Scope, Target
from vulnpipe.core.models import Finding, Severity
from vulnpipe.enrichment import enricher
from vulnpipe.enrichment.enricher import (
    EnrichmentClients,
    build_enrichment,
    enrich_findings,
)
from vulnpipe.enrichment.epss_client import EpssClient, EpssScore
from vulnpipe.enrichment.nvd_client import CveDetail, NvdClient
from vulnpipe.processing.normalizer import make_finding

VEC_A = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
VEC_B = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


class _FakeNvd:
    def __init__(self, details: dict[str, CveDetail]) -> None:
        self._details = details
        self.calls: list[str] = []

    def get_cve(self, cve_id: str) -> CveDetail | None:
        self.calls.append(cve_id)
        return self._details.get(cve_id)

    def close(self) -> None:
        pass


class _FakeEpss:
    def __init__(self, scores: dict[str, EpssScore]) -> None:
        self._scores = scores
        self.calls: list[list[str]] = []

    def get_scores(self, cve_ids: Any) -> dict[str, EpssScore]:
        ids = list(cve_ids)
        self.calls.append(ids)
        return {cve: self._scores[cve] for cve in ids if cve in self._scores}

    def close(self) -> None:
        pass


def _finding(**kwargs: Any) -> Finding:
    params: dict[str, Any] = {"source": "zap", "host": "app.example.com", "title": "Issue"}
    params.update(kwargs)
    return make_finding(**params)


# --------------------------------------------------------------------------- #
# enrich_findings: filling fields
# --------------------------------------------------------------------------- #
def test_enrich_fills_cvss_and_epss() -> None:
    finding = _finding(title="Vulnerable component", cve_ids=["CVE-2021-0002"])
    nvd = _FakeNvd({"CVE-2021-0002": CveDetail("CVE-2021-0002", cvss_score=9.8, cvss_vector=VEC_B)})
    epss = _FakeEpss({"CVE-2021-0002": EpssScore("CVE-2021-0002", epss=0.8, percentile=0.95)})
    [enriched] = enrich_findings([finding], nvd=nvd, epss=epss)  # type: ignore[arg-type]
    assert enriched.cvss_score == 9.8
    assert enriched.cvss_vector == VEC_B
    assert enriched.epss_score == 0.8
    assert enriched.epss_percentile == 0.95


def test_enrich_is_additive_and_keeps_scanner_values() -> None:
    # A scanner already supplied a CVSS score; enrichment must not overwrite it,
    # but may fill the still-missing vector.
    finding = _finding(
        source="nmap", title="CVE-2021-0002", cve_ids=["CVE-2021-0002"], cvss_score=7.5
    )
    assert finding.cvss_score == 7.5 and finding.cvss_vector is None
    nvd = _FakeNvd({"CVE-2021-0002": CveDetail("CVE-2021-0002", cvss_score=9.8, cvss_vector=VEC_B)})
    [enriched] = enrich_findings([finding], nvd=nvd)  # type: ignore[arg-type]
    assert enriched.cvss_score == 7.5  # scanner value preserved
    assert enriched.cvss_vector == VEC_B  # missing field filled


def test_enrich_picks_worst_case_across_multiple_cves() -> None:
    finding = _finding(cve_ids=["CVE-2021-0001", "CVE-2021-0002"])
    nvd = _FakeNvd(
        {
            "CVE-2021-0001": CveDetail("CVE-2021-0001", cvss_score=5.0, cvss_vector=VEC_A),
            "CVE-2021-0002": CveDetail("CVE-2021-0002", cvss_score=9.8, cvss_vector=VEC_B),
        }
    )
    epss = _FakeEpss(
        {
            "CVE-2021-0001": EpssScore("CVE-2021-0001", epss=0.10, percentile=0.50),
            "CVE-2021-0002": EpssScore("CVE-2021-0002", epss=0.80, percentile=0.95),
        }
    )
    [enriched] = enrich_findings([finding], nvd=nvd, epss=epss)  # type: ignore[arg-type]
    assert enriched.cvss_score == 9.8 and enriched.cvss_vector == VEC_B
    assert enriched.epss_score == 0.80 and enriched.epss_percentile == 0.95


def test_enrich_leaves_unknown_when_no_data() -> None:
    finding = _finding(cve_ids=["CVE-2021-9999"])
    nvd = _FakeNvd({})  # no detail for this CVE
    epss = _FakeEpss({})
    result = enrich_findings([finding], nvd=nvd, epss=epss)  # type: ignore[arg-type]
    assert result[0] is finding  # unchanged object: nothing to fill
    assert result[0].cvss_score is None and result[0].epss_score is None


def test_enrich_only_nvd_fills_cvss_only() -> None:
    finding = _finding(cve_ids=["CVE-2021-0002"])
    nvd = _FakeNvd({"CVE-2021-0002": CveDetail("CVE-2021-0002", cvss_score=9.8, cvss_vector=VEC_B)})
    [enriched] = enrich_findings([finding], nvd=nvd, epss=None)  # type: ignore[arg-type]
    assert enriched.cvss_score == 9.8
    assert enriched.epss_score is None


def test_enrich_only_epss_fills_epss_only() -> None:
    finding = _finding(cve_ids=["CVE-2021-0002"])
    epss = _FakeEpss({"CVE-2021-0002": EpssScore("CVE-2021-0002", epss=0.8)})
    [enriched] = enrich_findings([finding], nvd=None, epss=epss)  # type: ignore[arg-type]
    assert enriched.epss_score == 0.8
    assert enriched.epss_percentile is None  # not supplied
    assert enriched.cvss_score is None


def test_enrich_preserves_fingerprint_and_severity() -> None:
    finding = _finding(cve_ids=["CVE-2021-0002"], severity=Severity.MEDIUM)
    nvd = _FakeNvd({"CVE-2021-0002": CveDetail("CVE-2021-0002", cvss_score=9.8, cvss_vector=VEC_B)})
    [enriched] = enrich_findings([finding], nvd=nvd)  # type: ignore[arg-type]
    assert enriched.fingerprint == finding.fingerprint  # enriched fields aren't fingerprinted
    assert enriched.severity is Severity.MEDIUM  # enrichment is additive, never re-grades


def test_enrich_preserves_order() -> None:
    findings = [
        _finding(host="a", title="A", cve_ids=["CVE-2021-0002"]),
        _finding(host="b", title="B", cve_ids=["CVE-2021-0001"]),
    ]
    nvd = _FakeNvd({"CVE-2021-0002": CveDetail("CVE-2021-0002", cvss_score=9.8)})
    result = enrich_findings(findings, nvd=nvd)  # type: ignore[arg-type]
    assert [f.host for f in result] == ["a", "b"]


# --------------------------------------------------------------------------- #
# enrich_findings: short-circuits (no needless lookups)
# --------------------------------------------------------------------------- #
def test_enrich_empty_findings() -> None:
    assert enrich_findings([]) == []


def test_enrich_findings_without_cves_skip_lookups() -> None:
    nvd = _FakeNvd({"CVE-2021-0002": CveDetail("CVE-2021-0002", cvss_score=9.8)})
    epss = _FakeEpss({"CVE-2021-0002": EpssScore("CVE-2021-0002", epss=0.8)})
    findings = [_finding(title="Open port 80/tcp")]  # no CVEs
    result = enrich_findings(findings, nvd=nvd, epss=epss)  # type: ignore[arg-type]
    assert result == findings
    assert nvd.calls == []  # clients never consulted when there are no CVEs
    assert epss.calls == []


def test_enrich_looks_up_each_distinct_cve_once() -> None:
    findings = [
        _finding(host="a", title="A", cve_ids=["CVE-2021-0002"]),
        _finding(host="b", title="B", cve_ids=["CVE-2021-0002"]),  # same CVE
    ]
    nvd = _FakeNvd({"CVE-2021-0002": CveDetail("CVE-2021-0002", cvss_score=9.8)})
    enrich_findings(findings, nvd=nvd)  # type: ignore[arg-type]
    assert nvd.calls == ["CVE-2021-0002"]  # deduped to a single lookup


# --------------------------------------------------------------------------- #
# build_enrichment
# --------------------------------------------------------------------------- #
def _config(enrichment: EnrichmentConfig) -> Config:
    return Config(
        scope=Scope(hosts=["10.0.0.0/24"]),
        targets=[Target(host="10.0.0.5")],
        enrichment=enrichment,
    )


def test_build_enrichment_disabled_opens_no_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[Any] = []
    monkeypatch.setattr(enricher, "open_cache", lambda directory: opened.append(directory))
    clients = build_enrichment(_config(EnrichmentConfig(nvd_enabled=False, epss_enabled=False)))
    assert clients.nvd is None and clients.epss is None
    assert opened == []  # cache untouched when both sources are disabled


def test_build_enrichment_enabled_shares_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    sentinel = object()
    opened: list[Any] = []

    def fake_open(directory: Any) -> Any:
        opened.append(directory)
        return sentinel

    monkeypatch.setattr(enricher, "open_cache", fake_open)
    clients = build_enrichment(
        _config(EnrichmentConfig(nvd_enabled=True, epss_enabled=True, cache_dir=".cache"))
    )
    assert isinstance(clients.nvd, NvdClient)
    assert isinstance(clients.epss, EpssClient)
    assert opened == [".cache"]  # opened exactly once, shared by both clients


def test_enrichment_clients_close_delegates() -> None:
    nvd = _FakeNvd({})
    epss = _FakeEpss({})
    closed: list[str] = []
    nvd.close = lambda: closed.append("nvd")  # type: ignore[method-assign]
    epss.close = lambda: closed.append("epss")  # type: ignore[method-assign]
    EnrichmentClients(nvd=nvd, epss=epss).close()  # type: ignore[arg-type]
    assert closed == ["nvd", "epss"]
