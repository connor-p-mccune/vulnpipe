"""Unit tests for the terminal statistics view.

``render_stats`` renders through a fixed-width, non-terminal Rich console, so its
output is deterministic plain text (color markup is stripped) and assertable on
content.
"""

from vulnpipe.core.models import Finding, Severity
from vulnpipe.processing.normalizer import make_finding
from vulnpipe.reporting.stats import render_stats, stats_to_payload


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
            kev=True,
        ),
        make_finding(
            source="zap",
            host="app.lab.example.com",
            title="SQL Injection",
            severity=Severity.HIGH,
            port=443,
            plugin_id="40018",
        ),
        make_finding(
            source="nmap",
            host="10.0.0.5",
            title="Open port 22/tcp",
            severity=Severity.INFORMATIONAL,
        ),
    ]


def test_headline_and_kev_line() -> None:
    out = render_stats(_findings())
    assert "15 findings" not in out  # sanity: only what we passed
    assert "3 findings across 2 hosts" in out
    assert "1 known-exploited" in out


def test_severity_and_top_tables_present() -> None:
    out = render_stats(_findings())
    assert "By severity" in out
    assert "Top 10 by risk" in out
    assert "Top 10 hosts" in out
    assert "CVE-2021-42013" in out
    assert "critical" in out


def test_kev_marker_and_risk_ordering() -> None:
    out = render_stats(_findings())
    lines = out.splitlines()
    # The critical KEV finding is the first data row of the top-risks table.
    risk_rows = [line for line in lines if "CVE-2021-42013" in line]
    assert risk_rows and "!" in risk_rows[0]  # KEV marker present on that row


def test_no_kev_line_when_none_flagged() -> None:
    out = render_stats([make_finding(source="zap", host="h", title="X", severity=Severity.LOW)])
    assert "known-exploited" not in out


def test_remediation_table_present() -> None:
    out = render_stats(_findings())
    assert "Top 10 remediations" in out
    assert "Remediate: SQL Injection" in out


def test_owasp_table_present_when_cwes_map() -> None:
    finding = make_finding(
        source="zap", host="h", title="XSS", severity=Severity.HIGH, cwe_ids=["CWE-79"]
    )
    out = render_stats([finding])
    assert "OWASP Top 10 (2021)" in out
    assert "A03 Injection" in out


def test_owasp_table_absent_when_nothing_maps() -> None:
    out = render_stats(_findings())  # fixture findings carry no CWE references
    assert "OWASP Top 10" not in out


def test_empty_findings() -> None:
    out = render_stats([])
    assert "0 findings across 0 hosts" in out
    assert "No findings." in out


def test_is_deterministic() -> None:
    assert render_stats(_findings()) == render_stats(_findings())


# --------------------------------------------------------------------------- #
# JSON payload
# --------------------------------------------------------------------------- #
def test_payload_headline_and_breakdown() -> None:
    payload = stats_to_payload(_findings())
    assert payload["total"] == 3
    assert payload["hosts"] == 2
    assert payload["kev"] == 1
    assert payload["by_severity"]["critical"] == 1
    assert payload["remediation"]["actions"] >= 1


def test_payload_top_risks_and_worst_hosts_ordered() -> None:
    payload = stats_to_payload(_findings())
    # The critical KEV finding leads the top-risks list.
    assert payload["top_risks"][0]["title"] == "CVE-2021-42013"
    assert payload["top_risks"][0]["kev"] is True
    # 10.0.0.5 carries the critical, so it is the worst-affected host.
    assert payload["worst_hosts"][0]["host"] == "10.0.0.5"
    assert payload["worst_hosts"][0]["highest"] == "critical"


def test_payload_owasp_only_lists_mapped() -> None:
    finding = make_finding(
        source="zap", host="h", title="XSS", severity=Severity.HIGH, cwe_ids=["CWE-79"]
    )
    payload = stats_to_payload([finding])
    assert payload["owasp"] == {"A03": 1}
    assert payload["cwe_top_25"] == 1


def test_payload_empty() -> None:
    payload = stats_to_payload([])
    assert payload["total"] == 0
    assert payload["top_risks"] == []
    assert payload["worst_hosts"] == []
