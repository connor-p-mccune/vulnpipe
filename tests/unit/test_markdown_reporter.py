"""Unit tests for the Markdown reporter.

Cover the headline, the severity and findings tables, KEV/risk surfacing, cell
escaping, and determinism for fixed input.
"""

from vulnpipe.core.models import Confidence, Finding, Severity
from vulnpipe.processing.normalizer import make_finding
from vulnpipe.reporting.markdown_reporter import MarkdownReporter, render_markdown


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
            evidence="<script>alert(1)</script>",
        ),
    ]


def test_headline_reports_totals_and_kev() -> None:
    md = render_markdown(_findings())
    assert md.startswith("# vulnpipe security report")
    assert "**2 findings across 2 hosts**" in md
    assert "1 critical" in md and "1 high" in md
    assert "1 known-exploited (KEV)" in md


def test_severity_summary_table_lists_every_band() -> None:
    md = render_markdown(_findings())
    assert "## Severity summary" in md
    for label in ("Critical", "High", "Medium", "Low", "Info"):
        assert label in md


def test_findings_table_surfaces_risk_cvss_epss_and_kev() -> None:
    finding = _findings()[0]
    md = render_markdown([finding])
    # host:port, CVSS one-decimal, EPSS as a percentage, and the KEV marker.
    assert "10.0.0.5:80" in md
    assert "| 9.8 |" in md
    assert "94.5%" in md
    assert "⚠️ **Yes**" in md
    assert f"| {finding.risk_score} |" in md


def test_cell_escaping_neutralizes_pipes_and_newlines() -> None:
    finding = make_finding(
        source="zap",
        host="app.example.com",
        title="Weird | title\nwith a newline",
        severity=Severity.LOW,
    )
    md = render_markdown([finding])
    assert "Weird \\| title with a newline" in md  # pipe escaped, newline flattened


def test_non_kev_finding_has_no_exploited_marker() -> None:
    finding = make_finding(source="zap", host="h", title="Info", severity=Severity.INFORMATIONAL)
    md = render_markdown([finding])
    assert "Yes" not in md  # nothing flagged known-exploited
    assert "known-exploited" not in md  # headline omits the KEV clause


def test_owasp_table_lists_mapped_categories() -> None:
    findings = [
        make_finding(
            source="zap",
            host="app.example.com",
            title="SQL Injection",
            severity=Severity.HIGH,
            cwe_ids=["CWE-89"],
        ),
        make_finding(source="zap", host="app.example.com", title="No CWE", severity=Severity.LOW),
    ]
    md = render_markdown(findings)
    assert "## OWASP Top 10" in md
    assert "| A03 Injection | 1 |" in md
    assert "| _Not mapped_ | 1 |" in md


def test_owasp_table_omitted_when_nothing_maps() -> None:
    md = render_markdown(_findings())  # fixture findings carry no CWE references
    assert "## OWASP Top 10" not in md


def test_empty_report_renders_placeholder() -> None:
    md = render_markdown([])
    assert "**0 findings across 0 hosts**" in md
    assert "_No findings._" in md


def test_render_is_deterministic() -> None:
    reporter = MarkdownReporter()
    assert reporter.render(_findings()) == reporter.render(_findings())
    assert reporter.render(_findings()).endswith("\n")


def test_reporter_name() -> None:
    assert MarkdownReporter.name == "markdown"
