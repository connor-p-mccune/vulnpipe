"""Unit tests for the HTML reporter.

Covers the pure chart geometry, that the template renders without errors for varied
findings, that the report is deterministic, and -- importantly for a security tool
-- that scanner evidence is HTML-escaped rather than rendered as live markup.
"""

from vulnpipe.core.models import Confidence, Finding, Severity
from vulnpipe.processing.normalizer import make_finding
from vulnpipe.reporting.html_reporter import (
    SEVERITY_STYLES,
    HtmlReporter,
    build_severity_chart,
    render_html,
)
from vulnpipe.reporting.summary import SEVERITY_DISPLAY_ORDER, severity_counts

_MAX_BAR_WIDTH = 320


def _findings() -> list[Finding]:
    return [
        make_finding(
            source="nmap",
            host="10.0.0.10",
            title="OpenSSL vulnerability",
            severity=Severity.CRITICAL,
            port=443,
            plugin_id="vulners",
            cve_ids=["CVE-2021-44228"],
            cvss_score=9.8,
            epss_score=0.97,
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
        make_finding(
            source="nmap",
            host="10.0.0.10",
            title="Banner grab",
            severity=Severity.INFORMATIONAL,
            plugin_id="banner",
        ),
    ]


# --------------------------------------------------------------------------- #
# Chart geometry (pure)
# --------------------------------------------------------------------------- #
def test_chart_has_one_bar_per_severity_in_display_order() -> None:
    chart = build_severity_chart(severity_counts(_findings()))
    assert len(chart.bars) == len(SEVERITY_DISPLAY_ORDER)
    assert [bar.label for bar in chart.bars] == [
        SEVERITY_STYLES[severity].label for severity in SEVERITY_DISPLAY_ORDER
    ]


def test_chart_bars_scale_to_the_largest_count() -> None:
    counts = {
        Severity.CRITICAL: 2,
        Severity.HIGH: 1,
        Severity.MEDIUM: 0,
        Severity.LOW: 0,
        Severity.INFORMATIONAL: 1,
    }
    bars = {bar.label: bar for bar in build_severity_chart(counts).bars}
    assert bars["Critical"].width == _MAX_BAR_WIDTH  # busiest band fills the track
    assert bars["High"].width == _MAX_BAR_WIDTH // 2
    assert bars["Medium"].width == 0
    assert bars["Critical"].count == 2


def test_chart_all_zero_counts_have_zero_width() -> None:
    chart = build_severity_chart(severity_counts([]))
    assert all(bar.width == 0 for bar in chart.bars)
    assert chart.height > 0


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def test_render_produces_a_full_html_document() -> None:
    html = render_html(_findings())
    assert html.lstrip().startswith("<!DOCTYPE html>")
    assert "<html" in html and html.rstrip().endswith("</html>")
    assert "<svg" in html  # inline severity chart
    assert html.count("<rect") == len(SEVERITY_DISPLAY_ORDER)
    assert 'id="findings-table"' in html  # the sortable table
    assert "addEventListener" in html  # the client-side sorter


def test_render_includes_summary_and_per_host_breakdown() -> None:
    html = render_html(_findings())
    assert "Critical: 1" in html and "High: 1" in html
    assert "10.0.0.10" in html  # per-host section
    assert "app.lab.example.com" in html
    assert "OpenSSL vulnerability" in html  # title in the table
    assert "CVE-2021-44228" in html


def test_evidence_is_html_escaped_not_live_markup() -> None:
    html = render_html(_findings())
    # The reflected-XSS evidence must be inert text, never an executable element.
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert(1)</script>" not in html


def test_render_is_deterministic() -> None:
    assert render_html(_findings()) == render_html(_findings())


def test_render_empty_findings_does_not_error() -> None:
    html = render_html([])
    assert "No findings." in html
    assert "<svg" in html  # chart still renders (all-zero bars)


def test_reporter_name() -> None:
    assert HtmlReporter.name == "html"
