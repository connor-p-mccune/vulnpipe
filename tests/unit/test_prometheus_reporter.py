"""Unit tests for the Prometheus metrics reporter."""

from vulnpipe.core.models import Finding, Severity
from vulnpipe.processing.normalizer import make_finding
from vulnpipe.reporting.prometheus_reporter import PrometheusReporter, render_prometheus


def _findings() -> list[Finding]:
    return [
        make_finding(
            source="nmap",
            host="10.0.0.5",
            title="CVE-2021-42013",
            severity=Severity.CRITICAL,
            port=80,
            cve_ids=["CVE-2021-42013"],
            cvss_score=9.8,
            kev=True,
        ),
        make_finding(
            source="nmap", host="10.0.0.6", title="CVE-2021-23017", severity=Severity.HIGH
        ),
        make_finding(
            source="zap", host="app.lab.example.com", title="SQL Injection", severity=Severity.HIGH
        ),
    ]


def _series(text: str) -> dict[str, str]:
    """Map each non-comment metric line to its value (last token)."""
    series = {}
    for line in text.splitlines():
        if line and not line.startswith("#"):
            key, _, value = line.rpartition(" ")
            series[key] = value
    return series


def test_help_and_type_lines_present() -> None:
    text = render_prometheus(_findings())
    assert "# HELP vulnpipe_findings_total Number of findings by severity." in text
    assert "# TYPE vulnpipe_findings_total gauge" in text
    assert "# TYPE vulnpipe_known_exploited_total gauge" in text


def test_severity_and_source_series_values() -> None:
    series = _series(render_prometheus(_findings()))
    assert series['vulnpipe_findings_total{severity="critical"}'] == "1"
    assert series['vulnpipe_findings_total{severity="high"}'] == "2"
    assert series['vulnpipe_findings_total{severity="low"}'] == "0"
    assert series['vulnpipe_findings_by_source_total{source="nmap"}'] == "2"
    assert series['vulnpipe_findings_by_source_total{source="zap"}'] == "1"


def test_scalar_metrics() -> None:
    series = _series(render_prometheus(_findings()))
    assert series["vulnpipe_known_exploited_total"] == "1"
    assert series["vulnpipe_hosts_total"] == "3"
    assert series["vulnpipe_max_risk_score"] == "98"


def test_label_values_are_escaped() -> None:
    finding = make_finding(source='we"ird', host="h", title="X", severity=Severity.LOW)
    text = render_prometheus([finding])
    assert 'source="we\\"ird"' in text  # the double-quote is escaped


def test_empty_findings_render_zeroed_families() -> None:
    text = render_prometheus([])
    series = _series(text)
    assert series['vulnpipe_findings_total{severity="critical"}'] == "0"
    assert series["vulnpipe_hosts_total"] == "0"
    assert series["vulnpipe_max_risk_score"] == "0"
    # The by-source family has a HELP/TYPE header but no samples.
    assert "# TYPE vulnpipe_findings_by_source_total gauge" in text


def test_output_is_deterministic_and_newline_terminated() -> None:
    reporter = PrometheusReporter()
    first = reporter.render(_findings())
    assert first == reporter.render(_findings())
    assert first.endswith("\n")


def test_reporter_name() -> None:
    assert PrometheusReporter.name == "prometheus"
