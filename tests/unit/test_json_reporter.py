"""Unit tests for the canonical JSON reporter.

Covers the report envelope shape, deterministic output for fixed input, and the
round trip (build -> JSON -> reconstruct) that the HTML/SARIF renderers and the CI
differ depend on.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from vulnpipe.core.models import Confidence, Finding, Severity
from vulnpipe.processing.normalizer import make_finding
from vulnpipe.reporting.json_reporter import (
    REPORT_SCHEMA_VERSION,
    JsonReporter,
    build_report,
    load_findings,
    report_to_findings,
)


def _findings() -> list[Finding]:
    """A fixed, varied set of findings spanning severities and enriched fields."""
    return [
        make_finding(
            source="nmap",
            host="10.0.0.10",
            title="OpenSSL vulnerability",
            severity=Severity.CRITICAL,
            port=443,
            protocol="tcp",
            plugin_id="vulners",
            cve_ids=["CVE-2021-44228"],
            cwe_ids=["CWE-502"],
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            epss_score=0.97,
            epss_percentile=0.99,
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        ),
        make_finding(
            source="zap",
            host="app.lab.example.com",
            title="Cross Site Scripting (Reflected)",
            severity=Severity.HIGH,
            port=443,
            protocol="tcp",
            plugin_id="40012",
            confidence=Confidence.MEDIUM,
            evidence="<script>alert(1)</script>",
            metadata={"url": "https://app.lab.example.com/search?q=test", "param": "q"},
        ),
        make_finding(
            source="zap",
            host="app.lab.example.com",
            title="Timestamp Disclosure - Unix",
            severity=Severity.INFORMATIONAL,
            port=443,
            plugin_id="10096",
            confidence=Confidence.LOW,
        ),
    ]


def test_report_envelope_shape() -> None:
    report = build_report(_findings())
    assert list(report.keys()) == ["schema_version", "tool", "summary", "findings"]
    assert report["schema_version"] == REPORT_SCHEMA_VERSION
    assert report["tool"] == {"name": "vulnpipe", "version": report["tool"]["version"]}
    assert report["summary"] == {
        "total": 3,
        "hosts": 2,
        # Every severity band is present, in fixed worst-to-least order.
        "by_severity": {
            "critical": 1,
            "high": 1,
            "medium": 0,
            "low": 0,
            "informational": 1,
        },
    }
    assert len(report["findings"]) == 3
    # Each serialized finding carries its stable fingerprint.
    assert all("fingerprint" in finding for finding in report["findings"])


def test_render_is_deterministic_and_valid_json() -> None:
    reporter = JsonReporter()
    first = reporter.render(_findings())
    second = reporter.render(_findings())
    assert first == second  # byte-for-byte stable for fixed input
    assert first.endswith("\n")
    parsed = json.loads(first)
    assert parsed["findings"][0]["severity"] == "critical"  # input order preserved


def test_findings_preserve_input_order() -> None:
    report = build_report(_findings())
    assert [f["severity"] for f in report["findings"]] == ["critical", "high", "informational"]


def test_round_trip_reconstructs_findings_exactly() -> None:
    original = _findings()
    rebuilt = report_to_findings(build_report(original))
    assert rebuilt == original
    assert [f.fingerprint for f in rebuilt] == [f.fingerprint for f in original]


def test_round_trip_via_json_string() -> None:
    original = _findings()
    payload = json.loads(JsonReporter().render(original))
    assert report_to_findings(payload) == original


def test_load_findings_from_file(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    path.write_text(JsonReporter().render(_findings()), encoding="utf-8")
    assert load_findings(path) == _findings()


def test_load_findings_accepts_bare_list(tmp_path: Path) -> None:
    payload = [f.model_dump(mode="json") for f in _findings()]
    path = tmp_path / "bare.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert load_findings(path) == _findings()


def test_empty_report() -> None:
    report = build_report([])
    assert report["summary"]["total"] == 0
    assert report["summary"]["hosts"] == 0
    assert report["findings"] == []
    assert report_to_findings(report) == []


@pytest.mark.parametrize("payload", [{"findings": "not-a-list"}, {"findings": [42]}])
def test_report_to_findings_rejects_malformed(payload: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="finding"):
        report_to_findings(payload)


def test_load_findings_rejects_scalar_json(tmp_path: Path) -> None:
    path = tmp_path / "scalar.json"
    path.write_text("42", encoding="utf-8")
    with pytest.raises(ValueError, match="object or a list"):
        load_findings(path)
