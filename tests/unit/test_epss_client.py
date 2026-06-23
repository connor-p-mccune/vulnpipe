"""Unit tests for the EPSS client: pure parsing + the batched/cached HTTP path.

Parsing runs against a captured FIRST.org payload; ``get_scores`` drives a
respx-mocked endpoint with a real on-disk cache. No test hits the network.
"""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from vulnpipe.core.config import Config, EnrichmentConfig, Scope, Target
from vulnpipe.enrichment._http import open_cache
from vulnpipe.enrichment.epss_client import (
    DEFAULT_EPSS_URL,
    EpssClient,
    EpssScore,
    parse_epss_response,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _payload() -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURES / "sample_epss.json").read_text(encoding="utf-8"))
    return data


def _client(**kwargs: Any) -> EpssClient:
    kwargs.setdefault("sleep", lambda _seconds: None)
    kwargs.setdefault("min_request_interval", 0.0)
    return EpssClient(**kwargs)


def _filtered_epss(request: httpx.Request) -> httpx.Response:
    """Mock FIRST.org: return only the CVEs named in the request (as the real API does)."""
    wanted = set(request.url.params["cve"].split(","))
    rows = [row for row in _payload()["data"] if row["cve"] in wanted]
    return httpx.Response(200, json={"status": "OK", "data": rows})


# --------------------------------------------------------------------------- #
# Pure parsing
# --------------------------------------------------------------------------- #
def test_parse_fixture() -> None:
    scores = parse_epss_response(_payload())
    assert set(scores) == {"CVE-2021-44228", "CVE-2019-11358", "CVE-2020-11022"}
    log4shell = scores["CVE-2021-44228"]
    assert log4shell.epss == pytest.approx(0.97544)
    assert log4shell.percentile == pytest.approx(0.99997)


def test_parse_skips_invalid_entries() -> None:
    payload = {
        "data": [
            {"cve": "CVE-2021-44228", "epss": "0.5", "percentile": "0.9"},
            {"cve": "CVE-2021-0001", "epss": "1.5"},  # out of range -> skipped
            {"cve": "CVE-2021-0002", "epss": "abc"},  # unparseable -> skipped
            {"cve": "CVE-2021-0003"},  # missing epss -> skipped
            {"cve": "not-a-cve", "epss": "0.2"},  # invalid id -> skipped
            {"epss": "0.3"},  # no cve -> skipped
            "garbage",  # wrong type -> skipped
        ]
    }
    scores = parse_epss_response(payload)
    assert set(scores) == {"CVE-2021-44228"}


def test_parse_missing_percentile_is_none() -> None:
    scores = parse_epss_response({"data": [{"cve": "CVE-2021-44228", "epss": "0.5"}]})
    assert scores["CVE-2021-44228"].percentile is None


def test_parse_empty_or_malformed_payload() -> None:
    assert parse_epss_response({}) == {}
    assert parse_epss_response({"data": "nonsense"}) == {}
    assert parse_epss_response({"data": []}) == {}


# --------------------------------------------------------------------------- #
# get_scores: batched / cached HTTP
# --------------------------------------------------------------------------- #
@respx.mock
def test_get_scores_fetches_batch() -> None:
    respx.get(DEFAULT_EPSS_URL).mock(return_value=httpx.Response(200, json=_payload()))
    scores = _client().get_scores(["CVE-2021-44228", "CVE-2019-11358"])
    assert scores["CVE-2021-44228"].epss == pytest.approx(0.97544)
    assert scores["CVE-2019-11358"].epss == pytest.approx(0.09421)


@respx.mock
def test_get_scores_normalizes_and_dedupes_request() -> None:
    route = respx.get(DEFAULT_EPSS_URL).mock(return_value=httpx.Response(200, json=_payload()))
    _client().get_scores(["cve-2021-44228", "CVE-2021-44228", "garbage"])
    assert route.call_count == 1
    assert route.calls.last.request.url.params["cve"] == "CVE-2021-44228"


@respx.mock
def test_get_scores_caches_and_avoids_second_request(tmp_path: Path) -> None:
    route = respx.get(DEFAULT_EPSS_URL).mock(side_effect=_filtered_epss)
    cache = open_cache(tmp_path / "cache")
    client = _client(cache=cache)
    cves = ["CVE-2021-44228", "CVE-2019-11358"]
    first = client.get_scores(cves)
    second = client.get_scores(cves)
    assert first == second
    assert route.call_count == 1  # second call fully served from cache


@respx.mock
def test_get_scores_chunks_by_batch_size() -> None:
    route = respx.get(DEFAULT_EPSS_URL).mock(return_value=httpx.Response(200, json=_payload()))
    scores = _client(batch_size=1).get_scores(["CVE-2021-44228", "CVE-2019-11358"])
    assert route.call_count == 2  # one request per CVE
    assert set(scores) >= {"CVE-2021-44228", "CVE-2019-11358"}


@respx.mock
def test_get_scores_partial_cache_only_fetches_missing(tmp_path: Path) -> None:
    route = respx.get(DEFAULT_EPSS_URL).mock(side_effect=_filtered_epss)
    cache = open_cache(tmp_path / "cache")
    client = _client(cache=cache)
    client.get_scores(["CVE-2021-44228"])  # warms the cache for one CVE
    assert route.call_count == 1
    client.get_scores(["CVE-2021-44228", "CVE-2019-11358"])  # only the new one is fetched
    assert route.call_count == 2
    assert route.calls.last.request.url.params["cve"] == "CVE-2019-11358"


def test_get_scores_empty_input_makes_no_request() -> None:
    # No respx context: any network call would raise, proving none is made.
    assert _client().get_scores([]) == {}
    assert _client().get_scores(["not-a-cve"]) == {}


@respx.mock
def test_get_scores_network_error_returns_empty() -> None:
    respx.get(DEFAULT_EPSS_URL).mock(side_effect=httpx.ConnectError("down"))
    assert _client(max_attempts=2).get_scores(["CVE-2021-44228"]) == {}


@respx.mock
def test_get_scores_non_200_returns_empty() -> None:
    respx.get(DEFAULT_EPSS_URL).mock(return_value=httpx.Response(400))
    assert _client().get_scores(["CVE-2021-44228"]) == {}


def test_epss_score_defaults() -> None:
    assert EpssScore(cve_id="CVE-2021-44228", epss=0.5).percentile is None


# --------------------------------------------------------------------------- #
# from_config
# --------------------------------------------------------------------------- #
def _config(enrichment: EnrichmentConfig) -> Config:
    return Config(
        scope=Scope(hosts=["10.0.0.0/24"]),
        targets=[Target(host="10.0.0.5")],
        enrichment=enrichment,
    )


def test_from_config_disabled_returns_none() -> None:
    assert EpssClient.from_config(_config(EnrichmentConfig(epss_enabled=False))) is None


def test_from_config_enabled_builds_client() -> None:
    client = EpssClient.from_config(_config(EnrichmentConfig(epss_enabled=True)))
    assert isinstance(client, EpssClient)
