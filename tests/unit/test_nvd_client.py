"""Unit tests for the NVD client: pure parsing + the cached/mocked HTTP path.

The parsing tests run against a captured NVD 2.0 payload; the ``get_cve`` tests
drive a respx-mocked endpoint with a real on-disk cache. No test hits the network.
"""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from vulnpipe.core.config import Config, EnrichmentConfig, Scope, Target
from vulnpipe.enrichment._http import open_cache
from vulnpipe.enrichment.nvd_client import (
    DEFAULT_NVD_URL,
    CveDetail,
    NvdClient,
    parse_nvd_response,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _payload() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(
        (FIXTURES / "sample_nvd_cve.json").read_text(encoding="utf-8")
    )
    return data


def _client(**kwargs: Any) -> NvdClient:
    kwargs.setdefault("sleep", lambda _seconds: None)
    kwargs.setdefault("min_request_interval", 0.0)
    return NvdClient(**kwargs)


# --------------------------------------------------------------------------- #
# Pure parsing
# --------------------------------------------------------------------------- #
def test_parse_fixture_prefers_primary_v31() -> None:
    detail = parse_nvd_response(_payload(), "CVE-2021-44228")
    assert detail is not None
    assert detail.cve_id == "CVE-2021-44228"
    # Primary v3.1 (10.0) beats the Secondary v3.1 (8.1) and the v2 metric.
    assert detail.cvss_score == 10.0
    assert detail.cvss_version == "3.1"
    assert detail.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


def test_parse_fixture_description_picks_english() -> None:
    detail = parse_nvd_response(_payload(), "CVE-2021-44228")
    assert detail is not None
    assert detail.description is not None
    assert detail.description.startswith("Apache Log4j2 2.0-beta9")


def test_parse_fixture_cwes_filter_non_cwe_values() -> None:
    detail = parse_nvd_response(_payload(), "CVE-2021-44228")
    assert detail is not None
    # CWE-917 + CWE-502 kept; the "NVD-CWE-noinfo" placeholder dropped.
    assert detail.cwe_ids == ("CWE-917", "CWE-502")


def test_parse_fixture_references() -> None:
    detail = parse_nvd_response(_payload(), "CVE-2021-44228")
    assert detail is not None
    assert detail.references == (
        "https://logging.apache.org/log4j/2.x/security.html",
        "https://www.cve.org/CVERecord?id=CVE-2021-44228",
    )


def test_parse_returns_none_for_missing_cve() -> None:
    assert parse_nvd_response(_payload(), "CVE-1999-0001") is None


def test_parse_returns_none_for_empty_payload() -> None:
    assert parse_nvd_response({}, "CVE-2021-44228") is None
    assert parse_nvd_response({"vulnerabilities": "nonsense"}, "CVE-2021-44228") is None
    assert parse_nvd_response({"vulnerabilities": []}, "CVE-2021-44228") is None


def test_parse_falls_back_to_v2_when_only_v2_present() -> None:
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2002-0367",
                    "metrics": {
                        "cvssMetricV2": [
                            {
                                "type": "Primary",
                                "cvssData": {
                                    "version": "2.0",
                                    "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                                    "baseScore": 7.5,
                                },
                            }
                        ]
                    },
                }
            }
        ]
    }
    detail = parse_nvd_response(payload, "CVE-2002-0367")
    assert detail is not None
    assert detail.cvss_version == "2.0"
    assert detail.cvss_score == 7.5


def test_parse_unparseable_vector_salvages_base_score_only() -> None:
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2000-0002",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "type": "Primary",
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "GARBAGE",
                                    "baseScore": 5.5,
                                },
                            }
                        ]
                    },
                }
            }
        ]
    }
    detail = parse_nvd_response(payload, "CVE-2000-0002")
    assert detail is not None
    assert detail.cvss_score == 5.5
    assert detail.cvss_vector is None  # invalid vector is not emitted


def test_parse_no_metrics_leaves_cvss_unknown() -> None:
    payload = {"vulnerabilities": [{"cve": {"id": "CVE-2000-0003"}}]}
    detail = parse_nvd_response(payload, "CVE-2000-0003")
    assert detail is not None
    assert detail.cvss_score is None
    assert detail.cvss_vector is None
    assert detail.cvss_version is None


# --------------------------------------------------------------------------- #
# get_cve: cached / mocked HTTP
# --------------------------------------------------------------------------- #
@respx.mock
def test_get_cve_fetches_and_parses() -> None:
    respx.get(DEFAULT_NVD_URL).mock(return_value=httpx.Response(200, json=_payload()))
    detail = _client().get_cve("CVE-2021-44228")
    assert detail is not None
    assert detail.cvss_score == 10.0


@respx.mock
def test_get_cve_caches_and_avoids_second_request(tmp_path: Path) -> None:
    route = respx.get(DEFAULT_NVD_URL).mock(return_value=httpx.Response(200, json=_payload()))
    cache = open_cache(tmp_path / "cache")
    client = _client(cache=cache)
    first = client.get_cve("CVE-2021-44228")
    second = client.get_cve("cve-2021-44228")  # different case -> same cache key
    assert first == second
    assert first is not None and first.cvss_score == 10.0
    assert route.call_count == 1  # the second lookup is served from the cache


@respx.mock
def test_get_cve_sends_api_key_header() -> None:
    route = respx.get(DEFAULT_NVD_URL).mock(return_value=httpx.Response(200, json=_payload()))
    _client(api_key="secret-key").get_cve("CVE-2021-44228")
    assert route.calls.last.request.headers["apikey"] == "secret-key"


@respx.mock
def test_get_cve_404_returns_none() -> None:
    respx.get(DEFAULT_NVD_URL).mock(return_value=httpx.Response(404))
    assert _client().get_cve("CVE-2021-44228") is None


@respx.mock
def test_get_cve_network_error_returns_none() -> None:
    respx.get(DEFAULT_NVD_URL).mock(side_effect=httpx.ConnectError("down"))
    assert _client(max_attempts=2).get_cve("CVE-2021-44228") is None


@respx.mock
def test_get_cve_invalid_id_makes_no_request() -> None:
    route = respx.get(DEFAULT_NVD_URL).mock(return_value=httpx.Response(200, json=_payload()))
    assert _client().get_cve("not-a-cve") is None
    assert route.call_count == 0


def test_cve_detail_defaults() -> None:
    detail = CveDetail(cve_id="CVE-2021-44228")
    assert detail.cwe_ids == ()
    assert detail.references == ()
    assert detail.cvss_score is None


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
    assert NvdClient.from_config(_config(EnrichmentConfig(nvd_enabled=False))) is None


def test_from_config_enabled_builds_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    client = NvdClient.from_config(_config(EnrichmentConfig(nvd_enabled=True)))
    assert isinstance(client, NvdClient)
