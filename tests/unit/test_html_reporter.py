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
    risk_css,
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


def test_render_supports_light_and_dark_themes() -> None:
    html = render_html(_findings())
    # CSS custom properties plus a dark-scheme media query drive theming with no JS.
    assert "@media (prefers-color-scheme: dark)" in html
    assert "var(--bg)" in html and "var(--fg)" in html


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


# --------------------------------------------------------------------------- #
# Risk band coloring + KEV surfacing
# --------------------------------------------------------------------------- #
def test_risk_css_bands() -> None:
    assert risk_css(95) == "sev-critical"
    assert risk_css(70) == "sev-high"
    assert risk_css(40) == "sev-medium"
    assert risk_css(10) == "sev-low"
    assert risk_css(0) == "sev-informational"


def _kev_finding() -> Finding:
    return make_finding(
        source="nmap",
        host="10.0.0.5",
        title="CVE-2021-42013",
        severity=Severity.CRITICAL,
        port=80,
        plugin_id="vulners",
        cve_ids=["CVE-2021-42013"],
        cvss_score=9.8,
        epss_score=0.94,
        kev=True,
    )


def test_render_surfaces_kev_and_risk() -> None:
    html = render_html([_kev_finding()])
    assert "known-exploited" in html  # the summary card label
    assert "Known-exploited" in html  # the per-host KEV badge
    assert "badge-kev" in html
    assert 'id="severity-filter"' in html  # the interactive filter toolbar
    assert 'id="kev-only"' in html
    # EPSS is rendered as a percentage in the table.
    assert "94.0%" in html


def test_render_marks_kev_rows() -> None:
    html = render_html([_kev_finding()])
    assert 'data-kev="1"' in html
    assert 'data-severity="critical"' in html


# --------------------------------------------------------------------------- #
# OWASP Top 10 / CWE Top 25 surfacing
# --------------------------------------------------------------------------- #
def test_render_owasp_section_and_top25_card() -> None:
    finding = make_finding(
        source="zap",
        host="app.lab.example.com",
        title="Cross Site Scripting (Reflected)",
        severity=Severity.HIGH,
        plugin_id="40012",
        cwe_ids=["CWE-79"],
    )
    html = render_html([finding])
    assert "OWASP Top 10 (2021)" in html
    assert "badge-owasp" in html and ">A03<" in html
    assert "Injection" in html
    assert "CWE Top 25" in html  # CWE-79 is a Top 25 weakness -> the card counts it
    assert ">A03</td>" in html  # the findings-table OWASP column


def test_render_owasp_empty_state_when_nothing_maps() -> None:
    html = render_html(_findings())  # fixture findings carry no CWE references
    assert "No findings map to an OWASP Top 10 category." in html


# --------------------------------------------------------------------------- #
# Expandable finding details
# --------------------------------------------------------------------------- #
def test_details_disclosure_renders_description_solution_and_links() -> None:
    finding = make_finding(
        source="zap",
        host="app.lab.example.com",
        title="SQL Injection",
        severity=Severity.HIGH,
        plugin_id="40018",
        description="User input reaches the query unparameterized.",
        solution="Use parameterized statements.",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        references=["https://owasp.org/www-community/attacks/SQL_Injection", "see vendor notes"],
    )
    html = render_html([finding])
    assert "<details" in html and "<summary>Details</summary>" in html
    assert "User input reaches the query unparameterized." in html
    assert "Remediation:" in html and "Use parameterized statements." in html
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in html
    # https references become links; a non-URL reference stays plain text.
    assert 'href="https://owasp.org/www-community/attacks/SQL_Injection"' in html
    assert "see vendor notes" in html
    assert 'href="see vendor notes"' not in html


def test_details_reference_list_is_capped() -> None:
    refs = [f"https://example.com/ref/{index}" for index in range(8)]
    finding = make_finding(
        source="nmap", host="10.0.0.5", title="CVE-0000-0000 style", references=refs
    )
    html = render_html([finding])
    assert "https://example.com/ref/4" in html  # the first five render
    assert "https://example.com/ref/5" not in html
    assert "+ 3 more reference(s)" in html


def test_details_absent_without_detail_fields() -> None:
    finding = make_finding(source="nmap", host="10.0.0.5", title="Open port 22/tcp")
    html = render_html([finding])
    assert "<details" not in html
