"""Edge-case / defensive-branch coverage for the enrichment modules.

These exercise the malformed-input guards in the pure parsers and the small
lifecycle/short-circuit branches, so the package stays robust against junk API
responses. Everything here is offline (no real HTTP, no real cache).
"""

from decimal import Decimal
from typing import Any

import httpx
import pytest
import respx

from vulnpipe.enrichment import cvss as cvss_mod
from vulnpipe.enrichment._http import HttpJsonClient
from vulnpipe.enrichment.cvss import _coerce_score
from vulnpipe.enrichment.enricher import EnrichmentClients, enrich_findings
from vulnpipe.enrichment.epss_client import (
    DEFAULT_EPSS_URL,
    EpssClient,
    EpssScore,
    parse_epss_response,
)
from vulnpipe.enrichment.nvd_client import (
    DEFAULT_NVD_URL,
    CveDetail,
    NvdClient,
    _choose_entry,
    _english_description,
    _extract_cvss,
    _extract_cwes,
    _extract_references,
    _select_metric,
    parse_nvd_response,
)
from vulnpipe.processing.normalizer import make_finding

V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def _noop(_seconds: float) -> None:
    return None


# --------------------------------------------------------------------------- #
# cvss._coerce_score and the parse_vector score guard
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (Decimal("7.5"), 7.5),
        (7.5, 7.5),
        ("not-a-number", None),
        (float("nan"), None),
        (11.0, None),
        (-0.5, None),
    ],
)
def test_coerce_score(value: Any, expected: float | None) -> None:
    assert _coerce_score(value) == expected


def test_parse_vector_rejects_unscorable_metric(monkeypatch: pytest.MonkeyPatch) -> None:
    # A structurally-valid vector whose score cannot be coerced -> unknown, not kept.
    monkeypatch.setattr(cvss_mod, "_coerce_score", lambda _value: None)
    assert cvss_mod.parse_vector(V31) is None


# --------------------------------------------------------------------------- #
# HttpJsonClient throttle: no sleep once the interval has already elapsed
# --------------------------------------------------------------------------- #
def test_throttle_skips_sleep_when_interval_elapsed(monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []
    ticks = iter([1000.0, 1010.0, 1010.0])
    monkeypatch.setattr("vulnpipe.enrichment._http.time.monotonic", lambda: next(ticks))
    client = HttpJsonClient(min_request_interval=5.0, sleep=slept.append)
    client._throttle()  # records the first timestamp
    client._throttle()  # 10s elapsed of a 5s interval -> no wait needed
    assert slept == []


# --------------------------------------------------------------------------- #
# NVD pure-parser guards
# --------------------------------------------------------------------------- #
def test_english_description_guards() -> None:
    assert _english_description({}) is None
    assert _english_description({"descriptions": "x"}) is None
    payload = {
        "descriptions": [
            "junk",  # non-mapping entry
            {"lang": "en", "value": 123},  # non-str value
            {"lang": "en", "value": "   "},  # empty value
            {"lang": "fr", "value": "un"},  # first usable non-en -> fallback
            {"lang": "de", "value": "zwei"},  # fallback already set
        ]
    }
    assert _english_description(payload) == "un"  # no English present -> fallback


def test_choose_entry_prefers_primary_else_first() -> None:
    assert _choose_entry([]) is None
    assert _choose_entry([123, "x"]) is None
    first = {"type": "Secondary", "n": 1}
    assert _choose_entry([123, first, {"type": "Secondary", "n": 2}]) is first
    primary = {"type": "Primary"}
    assert _choose_entry([{"type": "Secondary"}, primary]) is primary


def test_select_metric_guards() -> None:
    assert _select_metric({}) is None
    assert _select_metric({"cvssMetricV31": "not-a-list"}) is None
    assert _select_metric({"cvssMetricV31": [123]}) is None  # no well-formed entry
    # First key's cvssData is not a mapping -> fall through to the next key.
    data, version = _select_metric(
        {
            "cvssMetricV31": [{"cvssData": "nope"}],
            "cvssMetricV30": [{"cvssData": {"baseScore": 1.0}}],
        }
    )
    assert version == "3.0" and data == {"baseScore": 1.0}


def test_extract_cvss_without_usable_metrics() -> None:
    assert _extract_cvss({}) == (None, None, None)
    assert _extract_cvss({"metrics": "x"}) == (None, None, None)
    assert _extract_cvss({"metrics": {}}) == (None, None, None)


def test_extract_cvss_unparseable_vector_without_base_score() -> None:
    # Bad vector AND no usable base score -> nothing is salvaged.
    cve = {
        "metrics": {
            "cvssMetricV31": [
                {"type": "Primary", "cvssData": {"version": "3.1", "vectorString": "GARBAGE"}}
            ]
        }
    }
    assert _extract_cvss(cve) == (None, None, None)


def test_extract_cwes_guards() -> None:
    assert _extract_cwes({}) == ()
    assert _extract_cwes({"weaknesses": "x"}) == ()
    payload = {
        "weaknesses": [
            "junk",  # non-mapping weakness
            {"description": "not-a-list"},
            {
                "description": [
                    123,
                    {"value": 456},
                    {"value": "NVD-CWE-noinfo"},
                    {"value": "CWE-79"},
                ]
            },
        ]
    }
    assert _extract_cwes(payload) == ("CWE-79",)


def test_extract_references_guards() -> None:
    assert _extract_references({}) == ()
    assert _extract_references({"references": "x"}) == ()
    payload = {"references": ["junk", {"url": 123}, {"url": "  "}, {"url": "https://a"}]}
    assert _extract_references(payload) == ("https://a",)


def test_parse_nvd_response_skips_malformed_entries() -> None:
    payload = {
        "vulnerabilities": [
            "junk",  # non-mapping item
            {"no_cve": 1},  # missing cve
            {"cve": "not-a-map"},  # cve not a mapping
            {"cve": {"id": 123}},  # non-str id
            {"cve": {"id": "CVE-2021-0002"}},  # the match (no metrics)
        ]
    }
    detail = parse_nvd_response(payload, "CVE-2021-0002")
    assert detail is not None
    assert detail.cve_id == "CVE-2021-0002"
    assert detail.cvss_score is None


# --------------------------------------------------------------------------- #
# NVD client: lifecycle + remaining HTTP branches
# --------------------------------------------------------------------------- #
def test_nvd_accepts_injected_http_client() -> None:
    custom = HttpJsonClient(min_request_interval=0.0, sleep=_noop)
    client = NvdClient(http=custom)
    assert client._http is custom


@respx.mock
def test_nvd_forbidden_returns_none() -> None:
    respx.get(DEFAULT_NVD_URL).mock(return_value=httpx.Response(403))
    assert NvdClient(min_request_interval=0.0, sleep=_noop).get_cve("CVE-2021-44228") is None


@respx.mock
def test_nvd_non_mapping_body_returns_none() -> None:
    respx.get(DEFAULT_NVD_URL).mock(return_value=httpx.Response(200, json=[1, 2, 3]))
    assert NvdClient(min_request_interval=0.0, sleep=_noop).get_cve("CVE-2021-44228") is None


def test_nvd_close_is_safe() -> None:
    NvdClient(min_request_interval=0.0, sleep=_noop).close()


# --------------------------------------------------------------------------- #
# EPSS client: parser + lifecycle + remaining HTTP branches
# --------------------------------------------------------------------------- #
def test_epss_parse_unit_float_via_response() -> None:
    payload = {
        "data": [
            {"cve": "CVE-2021-0001", "epss": None},  # missing value
            {"cve": "CVE-2021-0002", "epss": True},  # bool is not a score
            {"cve": "CVE-2021-0004", "epss": "nan"},  # NaN is not a score
            {"cve": "CVE-2021-0003", "epss": "0.5"},  # valid
        ]
    }
    assert set(parse_epss_response(payload)) == {"CVE-2021-0003"}


def test_epss_accepts_injected_http_client() -> None:
    custom = HttpJsonClient(min_request_interval=0.0, sleep=_noop)
    client = EpssClient(http=custom)
    assert client._http is custom


def test_epss_fetch_batch_empty_makes_no_request() -> None:
    assert EpssClient(min_request_interval=0.0, sleep=_noop)._fetch_batch([]) == {}


@respx.mock
def test_epss_non_mapping_body_returns_empty() -> None:
    respx.get(DEFAULT_EPSS_URL).mock(return_value=httpx.Response(200, json=[1, 2, 3]))
    assert EpssClient(min_request_interval=0.0, sleep=_noop).get_scores(["CVE-2021-44228"]) == {}


def test_epss_close_is_safe() -> None:
    EpssClient(min_request_interval=0.0, sleep=_noop).close()


# --------------------------------------------------------------------------- #
# Enricher: remaining branches
# --------------------------------------------------------------------------- #
def test_enrichment_clients_close_with_no_clients() -> None:
    EnrichmentClients().close()  # both None -> no-op, must not raise


class _FakeNvd:
    def __init__(self, details: dict[str, CveDetail]) -> None:
        self._details = details

    def get_cve(self, cve_id: str) -> CveDetail | None:
        return self._details.get(cve_id)


class _FakeEpss:
    def __init__(self, scores: dict[str, EpssScore]) -> None:
        self._scores = scores

    def get_scores(self, cve_ids: Any) -> dict[str, EpssScore]:
        return {cve: self._scores[cve] for cve in cve_ids if cve in self._scores}


def test_enrich_mixed_findings_passes_through_the_cveless_one() -> None:
    with_cve = make_finding(source="zap", host="a", title="Has CVE", cve_ids=["CVE-2021-0002"])
    without_cve = make_finding(source="zap", host="b", title="No CVE")
    nvd = _FakeNvd({"CVE-2021-0002": CveDetail("CVE-2021-0002", cvss_score=9.8)})
    enriched = enrich_findings([with_cve, without_cve], nvd=nvd)  # type: ignore[arg-type]
    assert enriched[0].cvss_score == 9.8
    assert enriched[1] is without_cve  # the CVE-less finding is untouched


def test_enrich_fills_only_missing_epss_percentile() -> None:
    # epss_score already known; enrichment must keep it and only add the percentile.
    finding = make_finding(
        source="zap", host="a", title="X", cve_ids=["CVE-2021-0002"], epss_score=0.5
    )
    epss = _FakeEpss({"CVE-2021-0002": EpssScore("CVE-2021-0002", epss=0.9, percentile=0.99)})
    [enriched] = enrich_findings([finding], epss=epss)  # type: ignore[arg-type]
    assert enriched.epss_score == 0.5  # preserved
    assert enriched.epss_percentile == 0.99  # filled
