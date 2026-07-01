"""Unit tests for the CISA KEV client: pure parsing + the cached HTTP path.

Parsing runs against a captured KEV catalog fixture; ``get_catalog`` drives a
respx-mocked endpoint with a real on-disk cache. No test hits the network.
"""

import json
from pathlib import Path
from typing import Any

import httpx
import respx

from vulnpipe.core.config import Config, EnrichmentConfig, Scope, Target
from vulnpipe.enrichment._http import open_cache
from vulnpipe.enrichment.kev_client import (
    DEFAULT_KEV_URL,
    KevClient,
    KevEntry,
    parse_kev_catalog,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _payload() -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURES / "sample_kev.json").read_text(encoding="utf-8"))
    return data


def _client(**kwargs: Any) -> KevClient:
    kwargs.setdefault("sleep", lambda _seconds: None)
    return KevClient(**kwargs)


# --------------------------------------------------------------------------- #
# Pure parsing
# --------------------------------------------------------------------------- #
def test_parse_fixture() -> None:
    catalog = parse_kev_catalog(_payload())
    # The malformed "not-a-cve" row is dropped; the three real CVEs are kept.
    assert set(catalog) == {"CVE-2021-44228", "CVE-2021-42013", "CVE-2021-41773"}
    log4shell = catalog["CVE-2021-44228"]
    assert log4shell.vendor_project == "Apache"
    assert log4shell.product == "Log4j2"
    assert log4shell.date_added == "2021-12-10"
    assert log4shell.known_ransomware is True
    assert catalog["CVE-2021-42013"].known_ransomware is False  # "Unknown" -> False


def test_parse_skips_invalid_and_dedupes() -> None:
    payload = {
        "vulnerabilities": [
            {"cveID": "CVE-2021-44228", "vendorProject": "Apache"},
            {"cveID": "cve-2021-44228", "vendorProject": "Duplicate"},  # first wins
            {"cveID": "garbage"},  # invalid id -> skipped
            {"vendorProject": "no-id"},  # no cve -> skipped
            "nonsense",  # wrong type -> skipped
        ]
    }
    catalog = parse_kev_catalog(payload)
    assert set(catalog) == {"CVE-2021-44228"}
    assert catalog["CVE-2021-44228"].vendor_project == "Apache"  # first occurrence kept


def test_parse_empty_or_malformed_payload() -> None:
    assert parse_kev_catalog({}) == {}
    assert parse_kev_catalog({"vulnerabilities": "nonsense"}) == {}
    assert parse_kev_catalog({"vulnerabilities": []}) == {}


def test_kev_entry_defaults() -> None:
    entry = KevEntry(cve_id="CVE-2021-44228")
    assert entry.known_ransomware is False
    assert entry.date_added is None


# --------------------------------------------------------------------------- #
# get_catalog / queries: cached HTTP
# --------------------------------------------------------------------------- #
@respx.mock
def test_get_catalog_fetches_once_and_memoizes() -> None:
    route = respx.get(DEFAULT_KEV_URL).mock(return_value=httpx.Response(200, json=_payload()))
    client = _client()
    first = client.get_catalog()
    second = client.get_catalog()
    assert set(first) == {"CVE-2021-44228", "CVE-2021-42013", "CVE-2021-41773"}
    assert first is second  # memoized in-process
    assert route.call_count == 1  # fetched exactly once


@respx.mock
def test_get_catalog_uses_disk_cache(tmp_path: Path) -> None:
    route = respx.get(DEFAULT_KEV_URL).mock(return_value=httpx.Response(200, json=_payload()))
    cache = open_cache(tmp_path / "cache")
    _client(cache=cache).get_catalog()  # warms the disk cache
    assert route.call_count == 1
    # A fresh client sharing the cache serves the catalog without another request.
    fresh = _client(cache=cache).get_catalog()
    assert set(fresh) == {"CVE-2021-44228", "CVE-2021-42013", "CVE-2021-41773"}
    assert route.call_count == 1


@respx.mock
def test_is_known_exploited_and_lookup() -> None:
    respx.get(DEFAULT_KEV_URL).mock(return_value=httpx.Response(200, json=_payload()))
    client = _client()
    assert client.is_known_exploited("cve-2021-44228") is True  # normalized + matched
    assert client.is_known_exploited("CVE-2000-0000") is False
    assert client.is_known_exploited("not-a-cve") is False
    entry = client.lookup("CVE-2021-44228")
    assert entry is not None and entry.known_ransomware is True
    assert client.lookup("not-a-cve") is None


@respx.mock
def test_network_error_yields_empty_catalog() -> None:
    respx.get(DEFAULT_KEV_URL).mock(side_effect=httpx.ConnectError("down"))
    assert _client(max_attempts=2).get_catalog() == {}


@respx.mock
def test_retryable_status_yields_empty_catalog() -> None:
    respx.get(DEFAULT_KEV_URL).mock(return_value=httpx.Response(503))
    assert _client(max_attempts=2).get_catalog() == {}


@respx.mock
def test_non_retryable_non_200_yields_empty_catalog() -> None:
    respx.get(DEFAULT_KEV_URL).mock(return_value=httpx.Response(404))
    assert _client().get_catalog() == {}


class _FakeHttp:
    """A stand-in HTTP engine returning a canned ``(status, body)`` pair."""

    def __init__(self, response: tuple[int, Any]) -> None:
        self._response = response
        self.closed = False

    def get_json(self, url: str, *, params: Any = None) -> tuple[int, Any]:
        return self._response

    def close(self) -> None:
        self.closed = True


def test_non_mapping_body_yields_empty_catalog() -> None:
    http = _FakeHttp((200, ["not", "a", "mapping"]))
    assert _client(http=http).get_catalog() == {}  # type: ignore[arg-type]


def test_close_delegates_to_http() -> None:
    http = _FakeHttp((200, {"vulnerabilities": []}))
    client = _client(http=http)  # type: ignore[arg-type]
    client.close()
    assert http.closed is True


@respx.mock
def test_empty_catalog_is_not_disk_cached(tmp_path: Path) -> None:
    route = respx.get(DEFAULT_KEV_URL).mock(return_value=httpx.Response(500))
    cache = open_cache(tmp_path / "cache")
    assert _client(cache=cache, max_attempts=1).get_catalog() == {}
    # A fresh client must retry rather than serve a cached empty result.
    _client(cache=cache, max_attempts=1).get_catalog()
    assert route.call_count == 2


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
    assert KevClient.from_config(_config(EnrichmentConfig(kev_enabled=False))) is None


def test_from_config_enabled_builds_client() -> None:
    client = KevClient.from_config(_config(EnrichmentConfig(kev_enabled=True)))
    assert isinstance(client, KevClient)
