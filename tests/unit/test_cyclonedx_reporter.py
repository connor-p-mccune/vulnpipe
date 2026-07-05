"""Unit tests for the CycloneDX 1.5 vulnerability report (VDR) renderer."""

import json
import re
from datetime import UTC, datetime

import pytest

from vulnpipe.core.models import Finding, Severity
from vulnpipe.processing.normalizer import make_finding
from vulnpipe.reporting import available_formats, get_reporter
from vulnpipe.reporting.cyclonedx_reporter import (
    SPEC_VERSION,
    CyclonedxReporter,
    build_cyclonedx,
    render_cyclonedx,
)


def _network_finding(**overrides: object) -> Finding:
    """A network finding citing a real CVE, overridable per test."""
    base: dict[str, object] = {
        "source": "nmap",
        "host": "10.0.0.5",
        "port": 80,
        "title": "Apache httpd 2.4.49 path traversal",
        "severity": Severity.CRITICAL,
        "plugin_id": "vulners",
        "cve_ids": ["CVE-2021-42013"],
        "cwe_ids": ["CWE-22"],
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "solution": "Upgrade Apache httpd to 2.4.51 or later.",
        "references": ["https://httpd.apache.org/security/vulnerabilities_24.html"],
    }
    base.update(overrides)
    return make_finding(**base)  # type: ignore[arg-type]


def _sbom_finding(**overrides: object) -> Finding:
    """An SBOM-layer finding carrying a purl and an OSV id, overridable per test."""
    base: dict[str, object] = {
        "source": "sbom",
        "host": "acme-app",
        "title": "GHSA-8fww-64cx-x8p5: requests@2.19.0",
        "severity": Severity.MEDIUM,
        "plugin_id": "GHSA-8fww-64cx-x8p5",
        "solution": "Update requests to 2.20.0 or later.",
        "metadata": {
            "purl": "pkg:pypi/requests@2.19.0",
            "package": "requests",
            "package_version": "2.19.0",
            "osv_id": "GHSA-8fww-64cx-x8p5",
        },
    }
    base.update(overrides)
    return make_finding(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Vulnerabilities
# --------------------------------------------------------------------------- #
def test_cve_finding_yields_a_vulnerability_and_component() -> None:
    doc = build_cyclonedx([_network_finding()])
    assert len(doc["vulnerabilities"]) == 1
    vuln = doc["vulnerabilities"][0]
    assert vuln["id"] == "CVE-2021-42013"
    assert vuln["bom-ref"] == "CVE-2021-42013"
    assert vuln["source"] == {
        "name": "NVD",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
    }
    assert vuln["affects"] == [{"ref": "10.0.0.5:80"}]
    assert vuln["recommendation"] == "Upgrade Apache httpd to 2.4.51 or later."
    assert vuln["cwes"] == [22]
    # The affected asset is emitted as an application component the affects link resolves to.
    assert doc["components"] == [
        {"type": "application", "bom-ref": "10.0.0.5:80", "name": "10.0.0.5"}
    ]


def test_finding_without_vulnerability_id_yields_nothing() -> None:
    hygiene = make_finding(
        source="zap",
        host="app.lab.example.com",
        title="X-Content-Type-Options Header Missing",
        severity=Severity.LOW,
    )
    doc = build_cyclonedx([hygiene])
    assert doc["vulnerabilities"] == []
    assert doc["components"] == []


def test_sbom_finding_is_a_library_component_keyed_by_purl() -> None:
    doc = build_cyclonedx([_sbom_finding()])
    assert doc["components"] == [
        {
            "type": "library",
            "bom-ref": "pkg:pypi/requests@2.19.0",
            "purl": "pkg:pypi/requests@2.19.0",
            "name": "requests",
            "version": "2.19.0",
        }
    ]
    vuln = doc["vulnerabilities"][0]
    assert vuln["id"] == "GHSA-8fww-64cx-x8p5"
    assert vuln["source"] == {
        "name": "GitHub Advisory Database",
        "url": "https://github.com/advisories/GHSA-8fww-64cx-x8p5",
    }
    assert vuln["affects"] == [{"ref": "pkg:pypi/requests@2.19.0"}]


def test_cve_alias_is_preferred_over_the_osv_id() -> None:
    doc = build_cyclonedx([_sbom_finding(cve_ids=["CVE-2018-18074"])])
    assert [v["id"] for v in doc["vulnerabilities"]] == ["CVE-2018-18074"]


def test_non_cve_non_ghsa_id_uses_the_osv_source() -> None:
    finding = _sbom_finding(
        title="PYSEC-2021-1: example@1.0",
        plugin_id="PYSEC-2021-1",
        metadata={"purl": "pkg:pypi/example@1.0", "osv_id": "PYSEC-2021-1"},
    )
    vuln = build_cyclonedx([finding])["vulnerabilities"][0]
    assert vuln["source"] == {"name": "OSV", "url": "https://osv.dev/vulnerability/PYSEC-2021-1"}


def test_same_cve_on_two_hosts_groups_into_one_vuln_with_sorted_affects() -> None:
    doc = build_cyclonedx([_network_finding(host="10.0.0.9"), _network_finding(host="10.0.0.5")])
    assert len(doc["vulnerabilities"]) == 1
    assert doc["vulnerabilities"][0]["affects"] == [{"ref": "10.0.0.5:80"}, {"ref": "10.0.0.9:80"}]
    assert [c["bom-ref"] for c in doc["components"]] == ["10.0.0.5:80", "10.0.0.9:80"]


def test_host_without_port_is_the_bare_component_ref() -> None:
    vuln = build_cyclonedx([_network_finding(port=None)])["vulnerabilities"][0]
    assert vuln["affects"] == [{"ref": "10.0.0.5"}]


# --------------------------------------------------------------------------- #
# Ratings
# --------------------------------------------------------------------------- #
def test_rating_carries_severity_score_method_and_vector() -> None:
    rating = build_cyclonedx([_network_finding()])["vulnerabilities"][0]["ratings"][0]
    assert rating == {
        "source": {"name": "vulnpipe"},
        "severity": "critical",
        "score": 9.8,
        "method": "CVSSv31",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    }


def test_rating_without_cvss_is_qualitative_only() -> None:
    finding = make_finding(
        source="nmap",
        host="10.0.0.5",
        title="Some CVE",
        severity=Severity.HIGH,
        plugin_id="vulners",
        cve_ids=["CVE-2021-99999"],
    )
    rating = build_cyclonedx([finding])["vulnerabilities"][0]["ratings"][0]
    assert rating == {"source": {"name": "vulnpipe"}, "severity": "high"}


def test_informational_severity_maps_to_info() -> None:
    finding = _sbom_finding(severity=Severity.INFORMATIONAL, cvss_score=None, cvss_vector=None)
    rating = build_cyclonedx([finding])["vulnerabilities"][0]["ratings"][0]
    assert rating["severity"] == "info"


@pytest.mark.parametrize(
    ("vector", "method"),
    [
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "CVSSv4"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSSv31"),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSSv3"),
        ("AV:N/AC:L/Au:N/C:P/I:P/A:P", "CVSSv2"),
        ("something-unrecognized", "other"),
    ],
)
def test_cvss_method_is_detected_from_the_vector(vector: str, method: str) -> None:
    finding = _network_finding(cvss_score=7.5, cvss_vector=vector)
    assert build_cyclonedx([finding])["vulnerabilities"][0]["ratings"][0]["method"] == method


def test_cvss_score_without_a_vector_uses_the_other_method() -> None:
    finding = _network_finding(cvss_score=7.5, cvss_vector=None)
    rating = build_cyclonedx([finding])["vulnerabilities"][0]["ratings"][0]
    assert rating["method"] == "other"
    assert "vector" not in rating


# --------------------------------------------------------------------------- #
# CWEs, advisories, properties
# --------------------------------------------------------------------------- #
def test_cwes_are_parsed_deduped_and_sorted() -> None:
    finding = _network_finding(cwe_ids=["CWE-79", "CWE-22", "CWE-79", "NVD-CWE-noinfo"])
    assert build_cyclonedx([finding])["vulnerabilities"][0]["cwes"] == [22, 79]


def test_advisories_are_http_references_sorted() -> None:
    finding = _network_finding(
        references=["https://b.example/adv", "ftp://x/y", "https://a.example/adv"]
    )
    assert build_cyclonedx([finding])["vulnerabilities"][0]["advisories"] == [
        {"url": "https://a.example/adv"},
        {"url": "https://b.example/adv"},
    ]


def test_properties_carry_risk_kev_and_epss() -> None:
    finding = _network_finding(kev=True, epss_score=0.945)
    props = {
        p["name"]: p["value"]
        for p in build_cyclonedx([finding])["vulnerabilities"][0]["properties"]
    }
    assert props["vulnpipe:kev"] == "true"
    assert props["vulnpipe:epss"] == "0.94500"
    assert int(props["vulnpipe:risk_score"]) > 0


def test_kev_property_false_and_epss_absent_by_default() -> None:
    props = {
        p["name"]: p["value"]
        for p in build_cyclonedx([_network_finding()])["vulnerabilities"][0]["properties"]
    }
    assert props["vulnpipe:kev"] == "false"
    assert "vulnpipe:epss" not in props


def test_representative_is_the_worst_risk_finding() -> None:
    worst = _network_finding(host="10.0.0.5", description="Critical instance", kev=True)
    lesser = _network_finding(
        host="10.0.0.9", description="Lesser instance", severity=Severity.LOW, cvss_score=3.1
    )
    vuln = build_cyclonedx([lesser, worst])["vulnerabilities"][0]
    assert vuln["description"] == "Critical instance"
    assert vuln["ratings"][0]["severity"] == "critical"


# --------------------------------------------------------------------------- #
# Document envelope
# --------------------------------------------------------------------------- #
def test_document_envelope() -> None:
    doc = build_cyclonedx([_network_finding()])
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == SPEC_VERSION
    assert doc["version"] == 1
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert doc["metadata"]["tools"]["components"][0]["name"] == "vulnpipe"
    assert "timestamp" not in doc["metadata"]  # omitted unless supplied; the reporter stamps it


def test_serial_number_is_content_addressed() -> None:
    same = build_cyclonedx([_network_finding()])["serialNumber"]
    assert build_cyclonedx([_network_finding()])["serialNumber"] == same
    different = build_cyclonedx([_network_finding(cve_ids=["CVE-2021-41773"])])["serialNumber"]
    assert different != same


def test_serial_number_is_a_uuid_shape() -> None:
    serial = build_cyclonedx([_network_finding()])["serialNumber"]
    assert re.fullmatch(
        r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", serial
    )


def test_empty_findings_render_a_valid_empty_document() -> None:
    doc = json.loads(render_cyclonedx([]))
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["vulnerabilities"] == []
    assert doc["components"] == []


def test_render_is_deterministic_and_newline_terminated() -> None:
    first = render_cyclonedx([_network_finding(), _sbom_finding()])
    assert first == render_cyclonedx([_network_finding(), _sbom_finding()])
    assert first.endswith("\n")


# --------------------------------------------------------------------------- #
# Timestamps
# --------------------------------------------------------------------------- #
def test_explicit_string_timestamp_passes_through() -> None:
    doc = build_cyclonedx([], timestamp="2026-01-01T00:00:00Z")
    assert doc["metadata"]["timestamp"] == "2026-01-01T00:00:00Z"


def test_naive_datetime_is_taken_as_utc() -> None:
    doc = build_cyclonedx([], timestamp=datetime(2026, 1, 1, 12, 30, 0))
    assert doc["metadata"]["timestamp"] == "2026-01-01T12:30:00Z"


def test_reporter_honors_source_date_epoch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    doc = json.loads(CyclonedxReporter().render([_network_finding()]))
    assert doc["metadata"]["timestamp"] == datetime.fromtimestamp(1700000000, tz=UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    assert CyclonedxReporter().render([_network_finding()]) == CyclonedxReporter().render(
        [_network_finding()]
    )


def test_reporter_stamps_current_utc_without_the_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    doc = json.loads(CyclonedxReporter().render([]))
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", doc["metadata"]["timestamp"])


def test_malformed_source_date_epoch_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "not-a-number")
    with pytest.raises(ValueError, match="SOURCE_DATE_EPOCH"):
        CyclonedxReporter().render([])


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
def test_cyclonedx_is_a_registered_format() -> None:
    assert "cyclonedx" in available_formats()
    assert isinstance(get_reporter("cyclonedx"), CyclonedxReporter)
    assert CyclonedxReporter.name == "cyclonedx"
