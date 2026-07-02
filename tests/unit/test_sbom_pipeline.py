"""Unit tests for the standalone SBOM pipeline (load -> OSV -> enrich -> prioritize).

Drives the pipeline with an injected fake OSV client and a real on-disk cache, so
no network is touched. Enrichment (EPSS/KEV) is exercised via respx-mocked feeds in
the CLI/integration layer; here it is disabled to keep the unit focused on the
compose-and-order behavior.
"""

import json
from pathlib import Path
from typing import Any

import httpx
import respx

from vulnpipe.enrichment._http import open_cache
from vulnpipe.enrichment.epss_client import DEFAULT_EPSS_URL
from vulnpipe.enrichment.kev_client import DEFAULT_KEV_URL
from vulnpipe.sbom.osv_client import DEFAULT_OSV_URL, OsvVulnerability
from vulnpipe.sbom.pipeline import run_sbom_pipeline

_HIGH = OsvVulnerability(
    id="GHSA-high",
    summary="high severity",
    aliases=("CVE-2018-18074",),
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5
    fixed_versions=("2.20.0",),
)
_INFO = OsvVulnerability(id="GHSA-info", summary="no score")


class _FakeOsv:
    def __init__(self, by_key: dict[tuple[str, str], list[OsvVulnerability]]) -> None:
        self._by_key = by_key
        self.closed = False

    def query(self, purl: str, version: str) -> list[OsvVulnerability]:
        return self._by_key.get((purl.rsplit("@", 1)[0], version), [])

    def close(self) -> None:
        self.closed = True


def _write_sbom(tmp_path: Path, components: list[dict[str, Any]]) -> Path:
    path = tmp_path / "sbom.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "metadata": {"component": {"name": "acme-webapp"}},
                "components": components,
            }
        ),
        encoding="utf-8",
    )
    return path


def test_pipeline_analyzes_enriches_off_and_prioritizes(tmp_path: Path) -> None:
    sbom = _write_sbom(
        tmp_path,
        [
            {"name": "requests", "version": "2.19.0", "purl": "pkg:pypi/requests@2.19.0"},
            {"name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"},
        ],
    )
    osv = _FakeOsv(
        {
            ("pkg:pypi/requests", "2.19.0"): [_INFO, _HIGH],  # two advisories, one package
            ("pkg:npm/left-pad", "1.3.0"): [],  # clean
        }
    )
    findings = run_sbom_pipeline(
        sbom, enrich=False, osv=osv, cache=open_cache(tmp_path / "cache")  # type: ignore[arg-type]
    )
    # Both advisories become findings; prioritized so the High sorts before the Info.
    assert [f.title for f in findings] == [
        "GHSA-high: requests 2.19.0",
        "GHSA-info: requests 2.19.0",
    ]
    assert findings[0].severity.value == "high"


def test_pipeline_clean_sbom_yields_no_findings(tmp_path: Path) -> None:
    sbom = _write_sbom(tmp_path, [{"name": "safe", "version": "1.0", "purl": "pkg:pypi/safe@1.0"}])
    osv = _FakeOsv({})
    findings = run_sbom_pipeline(
        sbom, enrich=False, osv=osv, cache=open_cache(tmp_path / "cache")  # type: ignore[arg-type]
    )
    assert findings == []


def test_pipeline_does_not_close_injected_client(tmp_path: Path) -> None:
    sbom = _write_sbom(
        tmp_path, [{"name": "requests", "version": "2.19.0", "purl": "pkg:pypi/requests@2.19.0"}]
    )
    osv = _FakeOsv({("pkg:pypi/requests", "2.19.0"): [_HIGH]})
    run_sbom_pipeline(sbom, enrich=False, osv=osv, cache=open_cache(tmp_path / "c"))  # type: ignore[arg-type]
    assert osv.closed is False  # the caller owns an injected client


@respx.mock
def test_pipeline_enrich_applies_kev_from_advisory_cve(tmp_path: Path) -> None:
    # OSV reports an advisory carrying CVE-2018-18074; KEV lists that CVE as exploited.
    respx.get(DEFAULT_EPSS_URL).mock(return_value=httpx.Response(200, json={"data": []}))
    respx.get(DEFAULT_KEV_URL).mock(
        return_value=httpx.Response(
            200,
            json={"vulnerabilities": [{"cveID": "CVE-2018-18074", "vendorProject": "PSF"}]},
        )
    )
    sbom = _write_sbom(
        tmp_path, [{"name": "requests", "version": "2.19.0", "purl": "pkg:pypi/requests@2.19.0"}]
    )
    osv = _FakeOsv({("pkg:pypi/requests", "2.19.0"): [_HIGH]})
    findings = run_sbom_pipeline(
        sbom, enrich=True, osv=osv, cache=open_cache(tmp_path / "cache")  # type: ignore[arg-type]
    )
    assert len(findings) == 1
    assert findings[0].kev is True  # KEV enrichment flowed onto the SBOM finding


@respx.mock
def test_pipeline_builds_default_osv_client_and_cache(tmp_path: Path) -> None:
    # No injected client/cache: the pipeline builds its own OSV client over cache_dir.
    route = respx.post(DEFAULT_OSV_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "vulns": [
                    {
                        "id": "GHSA-real",
                        "severity": [
                            {
                                "type": "CVSS_V3",
                                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            }
                        ],
                    }
                ]
            },
        )
    )
    sbom = _write_sbom(
        tmp_path, [{"name": "requests", "version": "2.19.0", "purl": "pkg:pypi/requests@2.19.0"}]
    )
    findings = run_sbom_pipeline(sbom, enrich=False, cache_dir=str(tmp_path / "cache"))
    assert route.called
    assert [f.title for f in findings] == ["GHSA-real: requests 2.19.0"]
