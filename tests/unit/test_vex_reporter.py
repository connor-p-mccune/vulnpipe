"""Unit tests for the OpenVEX 0.2.0 report renderer."""

import json
import re
from datetime import UTC, datetime

import pytest

from vulnpipe.core.models import Finding, Severity
from vulnpipe.processing.normalizer import make_finding
from vulnpipe.reporting import available_formats, get_reporter
from vulnpipe.reporting.vex_reporter import (
    OPENVEX_CONTEXT,
    STATUS_AFFECTED,
    VexReporter,
    build_vex,
    render_vex,
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
        "cve_ids": ["CVE-2021-41773"],
        "solution": "Upgrade Apache httpd to 2.4.51 or later.",
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
            "osv_id": "GHSA-8fww-64cx-x8p5",
        },
    }
    base.update(overrides)
    return make_finding(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Statements
# --------------------------------------------------------------------------- #
def test_cve_finding_yields_an_affected_statement() -> None:
    doc = build_vex([_network_finding()])
    assert len(doc["statements"]) == 1
    statement = doc["statements"][0]
    assert statement["vulnerability"] == {
        "name": "CVE-2021-41773",
        "@id": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
    }
    assert statement["products"] == [{"@id": "10.0.0.5:80"}]
    assert statement["status"] == STATUS_AFFECTED
    assert statement["action_statement"] == "Upgrade Apache httpd to 2.4.51 or later."


def test_finding_without_vulnerability_id_yields_no_statement() -> None:
    hygiene = make_finding(
        source="zap",
        host="app.lab.example.com",
        title="X-Content-Type-Options Header Missing",
        severity=Severity.LOW,
    )
    doc = build_vex([hygiene])
    assert doc["statements"] == []


def test_one_statement_per_cve_when_a_finding_cites_several() -> None:
    finding = _network_finding(cve_ids=["CVE-2021-41773", "CVE-2021-42013"])
    names = [s["vulnerability"]["name"] for s in build_vex([finding])["statements"]]
    assert names == ["CVE-2021-41773", "CVE-2021-42013"]


def test_ghsa_only_advisory_falls_back_to_the_osv_id() -> None:
    statement = build_vex([_sbom_finding()])["statements"][0]
    assert statement["vulnerability"] == {
        "name": "GHSA-8fww-64cx-x8p5",
        "@id": "https://github.com/advisories/GHSA-8fww-64cx-x8p5",
    }
    # The purl is the product identity, surfaced under identifiers for consumers.
    assert statement["products"] == [
        {"@id": "pkg:pypi/requests@2.19.0", "identifiers": {"purl": "pkg:pypi/requests@2.19.0"}}
    ]


def test_cve_alias_is_preferred_over_the_osv_id() -> None:
    finding = _sbom_finding(cve_ids=["CVE-2018-18074"])
    names = [s["vulnerability"]["name"] for s in build_vex([finding])["statements"]]
    assert names == ["CVE-2018-18074"]


def test_unknown_id_scheme_gets_no_canonical_url() -> None:
    finding = _sbom_finding(
        title="PYSEC-2021-1: example@1.0",
        plugin_id="PYSEC-2021-1",
        metadata={"purl": "pkg:pypi/example@1.0", "osv_id": "PYSEC-2021-1"},
    )
    statement = build_vex([finding])["statements"][0]
    assert statement["vulnerability"] == {"name": "PYSEC-2021-1"}


def test_generic_action_when_no_remediation_is_known() -> None:
    statement = build_vex([_network_finding(solution=None)])["statements"][0]
    assert statement["action_statement"] == (
        "Review the referenced advisories and remediate the affected product."
    )


def test_host_without_port_is_the_bare_product_id() -> None:
    statement = build_vex([_network_finding(port=None)])["statements"][0]
    assert statement["products"] == [{"@id": "10.0.0.5"}]


# --------------------------------------------------------------------------- #
# Grouping and KEV
# --------------------------------------------------------------------------- #
def test_same_cve_and_action_group_into_one_statement_with_sorted_products() -> None:
    first = _network_finding(host="10.0.0.9")
    second = _network_finding(host="10.0.0.5")
    statements = build_vex([first, second])["statements"]
    assert len(statements) == 1
    assert statements[0]["products"] == [{"@id": "10.0.0.5:80"}, {"@id": "10.0.0.9:80"}]


def test_same_cve_with_different_actions_stays_distinct() -> None:
    concrete = _network_finding()
    generic = _network_finding(host="10.0.0.9", solution=None)
    statements = build_vex([concrete, generic])["statements"]
    assert len(statements) == 2
    assert {s["vulnerability"]["name"] for s in statements} == {"CVE-2021-41773"}


def test_kev_sets_status_notes_and_is_a_property_of_the_cve() -> None:
    kev = _network_finding(kev=True)
    # Same CVE seen elsewhere without KEV knowledge, and with a different action.
    other = _network_finding(host="10.0.0.9", solution=None)
    statements = build_vex([kev, other])["statements"]
    assert len(statements) == 2
    assert all("Known Exploited Vulnerabilities" in s["status_notes"] for s in statements)


def test_no_status_notes_without_kev() -> None:
    statement = build_vex([_network_finding()])["statements"][0]
    assert "status_notes" not in statement


# --------------------------------------------------------------------------- #
# Document envelope
# --------------------------------------------------------------------------- #
def test_document_envelope() -> None:
    doc = build_vex([_network_finding()])
    assert doc["@context"] == OPENVEX_CONTEXT
    assert doc["@id"].startswith("https://openvex.dev/docs/vulnpipe-")
    assert doc["author"] == "vulnpipe"
    assert doc["version"] == 1
    assert "timestamp" not in doc  # omitted unless supplied; the reporter stamps it


def test_author_is_configurable() -> None:
    assert build_vex([], author="acme security")["author"] == "acme security"


def test_document_id_is_content_addressed() -> None:
    same = build_vex([_network_finding()])["@id"]
    assert build_vex([_network_finding()])["@id"] == same
    different = build_vex([_network_finding(cve_ids=["CVE-2021-42013"])])["@id"]
    assert different != same


def test_empty_findings_render_a_valid_empty_document() -> None:
    doc = json.loads(render_vex([]))
    assert doc["statements"] == []
    assert doc["@context"] == OPENVEX_CONTEXT


def test_render_is_deterministic_and_newline_terminated() -> None:
    first = render_vex([_network_finding(), _sbom_finding()])
    assert first == render_vex([_network_finding(), _sbom_finding()])
    assert first.endswith("\n")


# --------------------------------------------------------------------------- #
# Timestamps
# --------------------------------------------------------------------------- #
def test_explicit_string_timestamp_passes_through() -> None:
    doc = build_vex([], timestamp="2026-01-01T00:00:00Z")
    assert doc["timestamp"] == "2026-01-01T00:00:00Z"


def test_aware_datetime_is_converted_to_utc() -> None:
    from datetime import timedelta, timezone

    eastern = timezone(timedelta(hours=-5))
    doc = build_vex([], timestamp=datetime(2026, 1, 1, 7, 30, 0, tzinfo=eastern))
    assert doc["timestamp"] == "2026-01-01T12:30:00Z"


def test_naive_datetime_is_taken_as_utc() -> None:
    doc = build_vex([], timestamp=datetime(2026, 1, 1, 12, 30, 0))
    assert doc["timestamp"] == "2026-01-01T12:30:00Z"


def test_reporter_honors_source_date_epoch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    doc = json.loads(VexReporter().render([_network_finding()]))
    assert doc["timestamp"] == datetime.fromtimestamp(1700000000, tz=UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    # And is byte-deterministic under a fixed epoch.
    assert VexReporter().render([_network_finding()]) == VexReporter().render([_network_finding()])


def test_reporter_stamps_current_utc_without_the_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    doc = json.loads(VexReporter().render([]))
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", doc["timestamp"])


def test_malformed_source_date_epoch_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "not-a-number")
    with pytest.raises(ValueError, match="SOURCE_DATE_EPOCH"):
        VexReporter().render([])


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
def test_vex_is_a_registered_format() -> None:
    assert "vex" in available_formats()
    assert isinstance(get_reporter("vex"), VexReporter)
    assert VexReporter.name == "vex"
