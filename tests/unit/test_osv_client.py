"""Unit tests for the OSV.dev client: pure parsing + the cached POST path.

Parsing runs against a captured OSV response fixture; ``query`` drives a
respx-mocked endpoint with a real on-disk cache. No test hits the network.
"""

import json
from pathlib import Path
from typing import Any

import httpx
import respx

from vulnpipe.enrichment._http import open_cache
from vulnpipe.sbom.osv_client import (
    DEFAULT_OSV_URL,
    OsvClient,
    OsvVulnerability,
    parse_osv_response,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _payload() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(
        (FIXTURES / "sample_osv_response.json").read_text(encoding="utf-8")
    )
    return data


def _client(**kwargs: Any) -> OsvClient:
    kwargs.setdefault("sleep", lambda _seconds: None)
    return OsvClient(**kwargs)


# --------------------------------------------------------------------------- #
# Pure parsing
# --------------------------------------------------------------------------- #
def test_parse_fixture_sorted_by_id() -> None:
    vulns = parse_osv_response(_payload(), purl="pkg:pypi/requests@2.19.0")
    # Two valid records; the id-less and non-mapping entries are dropped; id-sorted.
    assert [vuln.id for vuln in vulns] == ["GHSA-x84v-xcm2-53pg", "PYSEC-2023-74"]


def test_parse_extracts_aliases_cvss_fixed_and_references() -> None:
    vuln = parse_osv_response(_payload(), purl="pkg:pypi/requests@2.19.0")[0]
    assert vuln.aliases == ("CVE-2018-18074", "PYSEC-2018-28")
    assert vuln.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    # Only the fixed version for the queried package (requests), not the npm one.
    assert vuln.fixed_versions == ("2.20.0",)
    # References are de-duplicated in first-seen order.
    assert vuln.references == (
        "https://nvd.nist.gov/vuln/detail/CVE-2018-18074",
        "https://github.com/psf/requests/pull/4718",
    )


def test_parse_skips_unparseable_cvss_vector() -> None:
    # PYSEC-2023-74 has a valid v3 vector and a junk v2 vector; the valid one wins.
    vuln = parse_osv_response(_payload(), purl="pkg:pypi/requests@2.19.0")[1]
    assert vuln.cvss_vector == "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"


def test_parse_empty_or_malformed() -> None:
    assert parse_osv_response({}, purl="pkg:pypi/x@1") == []
    assert parse_osv_response({"vulns": "nope"}, purl="pkg:pypi/x@1") == []
    assert parse_osv_response({"vulns": []}, purl="pkg:pypi/x@1") == []


def test_vulnerability_defaults() -> None:
    vuln = OsvVulnerability(id="OSV-1")
    assert vuln.aliases == () and vuln.fixed_versions == () and vuln.cvss_vector is None


def test_parse_tolerates_malformed_nested_shapes() -> None:
    payload = {
        "vulns": [
            {
                "id": "OSV-MALFORMED",
                "severity": "not-a-list",
                "aliases": ["CVE-2020-0001", "CVE-2020-0001", 123],  # dupe + wrong type
                "references": "not-a-list",
                "affected": [
                    "not-a-mapping",
                    {
                        "package": {"purl": "pkg:pypi/other"},  # different package -> ignored
                        "ranges": [{"events": [{"fixed": "9.9.9"}]}],
                    },
                    {
                        "package": {"purl": "pkg:pypi/requests"},
                        "ranges": "not-a-list",
                    },
                    {
                        "package": {"purl": "pkg:pypi/requests"},
                        "ranges": ["not-a-mapping", {"events": "not-a-list"}],
                    },
                ],
            }
        ]
    }
    vuln = parse_osv_response(payload, purl="pkg:pypi/requests@2.19.0")[0]
    assert vuln.cvss_vector is None  # severity was not a list
    assert vuln.aliases == ("CVE-2020-0001",)  # de-duped, non-strings dropped
    assert vuln.references == ()
    assert vuln.fixed_versions == ()  # the 9.9.9 fix was for a different package


def test_parse_worst_cvss_vector_skips_non_mappings() -> None:
    payload = {
        "vulns": [
            {
                "id": "OSV-SEV",
                "severity": [
                    "not-a-mapping",
                    {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
                    {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
                ],
            }
        ]
    }
    vuln = parse_osv_response(payload, purl="pkg:pypi/x@1")[0]
    # The higher-scoring vector (C:H) wins over the lower (C:L).
    assert vuln.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"


def test_parse_references_dedup_and_non_mapping() -> None:
    payload = {
        "vulns": [
            {
                "id": "OSV-REF",
                "references": [
                    "not-a-mapping",
                    {"url": "https://a.example"},
                    {"url": "https://a.example"},
                    {"nourl": True},
                ],
            }
        ]
    }
    assert parse_osv_response(payload, purl="pkg:pypi/x@1")[0].references == ("https://a.example",)


def test_fixed_versions_included_when_affected_has_no_purl() -> None:
    payload = {
        "vulns": [
            {
                "id": "OSV-NOPURL",
                "affected": [{"ranges": [{"events": [{"fixed": "1.2.3"}, {"fixed": "1.2.3"}]}]}],
            }
        ]
    }
    # No purl on the affected entry: it is trusted (the record answered this query).
    assert parse_osv_response(payload, purl="pkg:pypi/x")[0].fixed_versions == ("1.2.3",)


# --------------------------------------------------------------------------- #
# query: cached POST
# --------------------------------------------------------------------------- #
@respx.mock
def test_query_posts_purl_and_version() -> None:
    route = respx.post(DEFAULT_OSV_URL).mock(return_value=httpx.Response(200, json=_payload()))
    vulns = _client().query("pkg:pypi/requests@2.19.0", "2.19.0")
    assert [vuln.id for vuln in vulns] == ["GHSA-x84v-xcm2-53pg", "PYSEC-2023-74"]
    body = json.loads(route.calls.last.request.content)
    assert body == {"package": {"purl": "pkg:pypi/requests"}, "version": "2.19.0"}


@respx.mock
def test_query_uses_disk_cache(tmp_path: Path) -> None:
    route = respx.post(DEFAULT_OSV_URL).mock(return_value=httpx.Response(200, json=_payload()))
    cache = open_cache(tmp_path / "cache")
    _client(cache=cache).query("pkg:pypi/requests@2.19.0", "2.19.0")
    assert route.call_count == 1
    fresh = _client(cache=cache).query("pkg:pypi/requests@2.19.0", "2.19.0")
    assert [vuln.id for vuln in fresh] == ["GHSA-x84v-xcm2-53pg", "PYSEC-2023-74"]
    assert route.call_count == 1  # served from disk, no second request


@respx.mock
def test_network_error_yields_empty(tmp_path: Path) -> None:
    respx.post(DEFAULT_OSV_URL).mock(side_effect=httpx.ConnectError("down"))
    assert _client(max_attempts=2).query("pkg:pypi/x@1", "1") == []


@respx.mock
def test_non_200_yields_empty() -> None:
    respx.post(DEFAULT_OSV_URL).mock(return_value=httpx.Response(404))
    assert _client().query("pkg:pypi/x@1", "1") == []


@respx.mock
def test_retryable_status_then_empty() -> None:
    respx.post(DEFAULT_OSV_URL).mock(return_value=httpx.Response(503))
    assert _client(max_attempts=2).query("pkg:pypi/x@1", "1") == []


class _FakeHttp:
    def __init__(self, response: tuple[int, Any]) -> None:
        self._response = response
        self.closed = False

    def post_json(self, url: str, *, json_body: Any) -> tuple[int, Any]:
        return self._response

    def close(self) -> None:
        self.closed = True


def test_non_mapping_body_yields_empty() -> None:
    client = _client(http=_FakeHttp((200, ["not", "a", "mapping"])))  # type: ignore[arg-type]
    assert client.query("pkg:pypi/x@1", "1") == []


def test_close_delegates_to_http() -> None:
    http = _FakeHttp((200, {"vulns": []}))
    client = _client(http=http)  # type: ignore[arg-type]
    client.close()
    assert http.closed is True
