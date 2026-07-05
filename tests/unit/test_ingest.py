"""Unit tests for third-party scanner ingestion (Trivy / Grype).

Parse the committed fixtures into findings and assert on the normalization: source,
host, severity mapping, CVSS/solution extraction, package metadata (so the
remediation planner can group them), deterministic ordering, and the error guards.
"""

import json
from pathlib import Path

import pytest

from vulnpipe.core.models import Finding, Severity
from vulnpipe.ingest import IngestError, available_ingesters, get_ingester, severity_from_label
from vulnpipe.ingest.grype import parse_grype
from vulnpipe.ingest.trivy import parse_trivy

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _load(name: str) -> object:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# Registry + severity mapping
# --------------------------------------------------------------------------- #
def test_available_and_get_ingester() -> None:
    assert available_ingesters() == ["grype", "trivy"]
    assert get_ingester("trivy") is parse_trivy
    assert get_ingester("grype") is parse_grype


def test_unknown_ingester_raises() -> None:
    with pytest.raises(IngestError, match="Unknown ingest format"):
        get_ingester("snyk")


def test_severity_from_label_maps_and_degrades() -> None:
    assert severity_from_label("CRITICAL") is Severity.CRITICAL
    assert severity_from_label("negligible") is Severity.INFORMATIONAL
    assert severity_from_label("weird") is Severity.INFORMATIONAL
    assert severity_from_label(None) is Severity.INFORMATIONAL


# --------------------------------------------------------------------------- #
# Trivy
# --------------------------------------------------------------------------- #
def _trivy() -> list[Finding]:
    return parse_trivy(_load("trivy_report.json"))


def test_trivy_parses_every_vulnerability() -> None:
    findings = _trivy()
    assert len(findings) == 3  # 2 os-pkg CVEs + 1 lang-pkg advisory; the empty result yields none
    assert all(finding.source == "trivy" for finding in findings)
    assert all(finding.host == "myapp:1.0" for finding in findings)


def test_trivy_maps_severity_cvss_and_solution() -> None:
    by_id = {finding.plugin_id: finding for finding in _trivy()}
    gzip = by_id["CVE-2022-1271"]
    assert gzip.severity is Severity.HIGH
    assert gzip.cvss_score == 8.8  # the highest V3Score across sources (nvd 8.8 > redhat 7.1)
    assert gzip.cvss_vector is not None and gzip.cvss_vector.startswith("CVSS:3.1")
    assert gzip.solution == "Update gzip to 1.10-4+deb11u1 or later."
    assert gzip.cve_ids == ("CVE-2022-1271",)
    assert gzip.cwe_ids == ("CWE-427",)
    assert gzip.metadata["package"] == "gzip"


def test_trivy_non_cve_id_kept_as_plugin_but_not_cve() -> None:
    ghsa = next(f for f in _trivy() if f.plugin_id == "GHSA-xxxx-yyyy-zzzz")
    assert ghsa.cve_ids == ()  # GHSA is not a CVE, so it is filtered from cve_ids
    assert ghsa.severity is Severity.MEDIUM
    assert ghsa.solution is None  # no FixedVersion -> no invented remediation


def test_trivy_ordering_is_deterministic_by_package() -> None:
    findings = _trivy()
    packages = [f.metadata.get("package") for f in findings]
    assert packages == sorted(packages)


def test_trivy_rejects_non_report() -> None:
    with pytest.raises(IngestError, match="Results"):
        parse_trivy({"not": "trivy"})
    with pytest.raises(IngestError, match="JSON object"):
        parse_trivy([1, 2, 3])


# --------------------------------------------------------------------------- #
# Grype
# --------------------------------------------------------------------------- #
def _grype() -> list[Finding]:
    return parse_grype(_load("grype_report.json"))


def test_grype_parses_matches_with_image_host() -> None:
    findings = _grype()
    assert len(findings) == 2
    assert all(finding.source == "grype" for finding in findings)
    assert all(finding.host == "myapp:1.0" for finding in findings)  # from source.target.userInput


def test_grype_maps_severity_cvss_and_fix() -> None:
    by_id = {finding.plugin_id: finding for finding in _grype()}
    gzip = by_id["CVE-2022-1271"]
    assert gzip.severity is Severity.HIGH
    assert gzip.cvss_score == 8.8
    assert gzip.solution == "Update gzip to 1.10-4+deb11u1 or later."
    assert gzip.metadata["purl"] == "pkg:deb/debian/gzip@1.10-4"


def test_grype_advisory_without_fix_or_cvss() -> None:
    ghsa = next(f for f in _grype() if f.plugin_id == "GHSA-aaaa-bbbb-cccc")
    assert ghsa.cvss_score is None
    assert ghsa.solution is None
    assert ghsa.severity is Severity.MEDIUM


def test_grype_host_falls_back_to_string_target() -> None:
    findings = parse_grype(
        {
            "matches": [{"vulnerability": {"id": "CVE-2021-1", "severity": "Low"}, "artifact": {}}],
            "source": {"type": "directory", "target": "/src"},
        }
    )
    assert findings[0].host == "/src"


def test_grype_rejects_non_report() -> None:
    with pytest.raises(IngestError, match="matches"):
        parse_grype({"not": "grype"})


# --------------------------------------------------------------------------- #
# Cross-scanner: imported findings feed the rest of the pipeline
# --------------------------------------------------------------------------- #
def test_imported_findings_group_in_the_remediation_planner() -> None:
    from vulnpipe.reporting.remediation import plan_remediations

    # A Trivy CVE and a Grype CVE on the same package should each yield a package action.
    actions = plan_remediations(_trivy() + _grype())
    titles = {action.title for action in actions}
    assert "Upgrade gzip" in titles  # metadata-driven package grouping works for imports
