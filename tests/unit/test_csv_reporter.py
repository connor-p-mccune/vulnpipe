"""Unit tests for the CSV reporter.

Parse the rendered CSV back with the stdlib ``csv`` module and assert on the header,
the column values (including computed fingerprint / risk score), quoting of awkward
cells, and determinism.
"""

import csv
import io

from vulnpipe.core.models import Confidence, Finding, Severity
from vulnpipe.processing.normalizer import make_finding
from vulnpipe.reporting.csv_reporter import CsvReporter, render_csv


def _findings() -> list[Finding]:
    return [
        make_finding(
            source="nmap",
            host="10.0.0.5",
            title="CVE-2021-42013",
            severity=Severity.CRITICAL,
            port=80,
            plugin_id="vulners",
            cve_ids=["CVE-2021-42013"],
            cwe_ids=["CWE-22"],
            cvss_score=9.8,
            epss_score=0.945,
            kev=True,
        ),
        make_finding(
            source="zap",
            host="app.lab.example.com",
            title="Cross Site Scripting (Reflected)",
            severity=Severity.HIGH,
            port=443,
            plugin_id="40012",
            confidence=Confidence.MEDIUM,
            metadata={"url": "https://app.lab.example.com/search?q=1"},
        ),
    ]


def _parse(text: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(text)))


def test_header_matches_columns() -> None:
    rows = _parse(render_csv(_findings()))
    assert rows[0].keys() >= {
        "fingerprint",
        "severity",
        "risk_score",
        "source",
        "host",
        "port",
        "title",
        "cvss_score",
        "epss_score",
        "kev",
        "cve_ids",
        "url",
    }


def test_row_values_and_computed_fields() -> None:
    finding = _findings()[0]
    row = _parse(render_csv([finding]))[0]
    assert row["severity"] == "critical"
    assert row["risk_score"] == str(finding.risk_score)
    assert row["fingerprint"] == finding.fingerprint
    assert row["cvss_score"] == "9.8"
    assert row["kev"] == "true"
    assert row["cve_ids"] == "CVE-2021-42013"
    assert row["cwe_ids"] == "CWE-22"


def test_missing_values_render_empty() -> None:
    finding = make_finding(source="zap", host="h", title="Info", severity=Severity.INFORMATIONAL)
    row = _parse(render_csv([finding]))[0]
    assert row["cvss_score"] == ""
    assert row["epss_score"] == ""
    assert row["kev"] == "false"
    assert row["confidence"] == ""
    assert row["url"] == ""
    assert row["port"] == ""


def test_url_pulled_from_metadata() -> None:
    row = _parse(render_csv([_findings()[1]]))[0]
    assert row["url"] == "https://app.lab.example.com/search?q=1"
    assert row["confidence"] == "medium"


def test_awkward_cells_are_quoted() -> None:
    finding = make_finding(
        source="zap",
        host="h",
        title='Comma, and "quote" here',
        severity=Severity.LOW,
    )
    text = render_csv([finding])
    # The stdlib writer quotes and escapes; round-tripping recovers the exact title.
    assert _parse(text)[0]["title"] == 'Comma, and "quote" here'


def test_render_is_deterministic_with_lf_terminators() -> None:
    reporter = CsvReporter()
    first = reporter.render(_findings())
    assert first == reporter.render(_findings())
    assert "\r" not in first  # LF-only, stable across platforms


def test_empty_report_is_header_only() -> None:
    text = render_csv([])
    lines = text.splitlines()
    assert len(lines) == 1  # header row, no data rows
    assert lines[0].startswith("fingerprint,severity,risk_score,")


def test_reporter_name() -> None:
    assert CsvReporter.name == "csv"
