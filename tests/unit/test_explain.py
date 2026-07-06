"""Unit tests for the `explain` command: selection, payload, and rendering."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vulnpipe.cli.main import app
from vulnpipe.core.models import Confidence, Finding, Severity
from vulnpipe.processing.normalizer import make_finding
from vulnpipe.reporting.explain import (
    ExplainError,
    explain_payload,
    render_explain,
    select_finding,
)
from vulnpipe.reporting.json_reporter import JsonReporter

runner = CliRunner()


def _kev_finding() -> Finding:
    return make_finding(
        source="nmap",
        host="10.0.0.5",
        port=80,
        title="CVE-2021-42013",
        severity=Severity.CRITICAL,
        plugin_id="vulners",
        cve_ids=["CVE-2021-42013"],
        cwe_ids=["CWE-22"],
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        kev=True,
        solution="Upgrade Apache httpd to 2.4.51 or later.",
        references=["https://httpd.apache.org/security/vulnerabilities_24.html"],
        metadata={"owner": "platform-team", "tags": ["infrastructure"]},
    )


def _web_finding() -> Finding:
    return make_finding(
        source="zap",
        host="app.lab.example.com",
        port=443,
        title="Cross Site Scripting (Reflected)",
        severity=Severity.HIGH,
        plugin_id="40012",
        cwe_ids=["CWE-79"],
    )


# --------------------------------------------------------------------------- #
# select_finding
# --------------------------------------------------------------------------- #
def test_select_by_full_fingerprint() -> None:
    finding = _kev_finding()
    assert select_finding([finding], fingerprint=finding.fingerprint) is finding


def test_select_by_unique_fingerprint_prefix() -> None:
    finding = _kev_finding()
    assert (
        select_finding([finding, _web_finding()], fingerprint=finding.fingerprint[:10]) is finding
    )


def test_select_by_ambiguous_prefix_raises() -> None:
    # Two entries sharing a fingerprint make any prefix of it ambiguous.
    finding = _kev_finding()
    with pytest.raises(ExplainError, match="ambiguous"):
        select_finding([finding, finding], fingerprint=finding.fingerprint[:8])


def test_select_by_short_or_unknown_fingerprint_raises() -> None:
    with pytest.raises(ExplainError, match="no finding"):
        select_finding([_kev_finding()], fingerprint="abc")  # < 7 chars, no exact match
    with pytest.raises(ExplainError, match="no finding"):
        select_finding([_kev_finding()], fingerprint="deadbeefdeadbeef")


def test_select_by_index() -> None:
    a, b = _kev_finding(), _web_finding()
    assert select_finding([a, b], index=2) is b


def test_select_by_index_out_of_range_raises() -> None:
    with pytest.raises(ExplainError, match="out of range"):
        select_finding([_kev_finding()], index=5)


def test_select_by_title_substring_case_insensitive() -> None:
    assert select_finding([_kev_finding(), _web_finding()], title="cross site") is not None


def test_select_by_title_no_match_raises() -> None:
    with pytest.raises(ExplainError, match="no finding matching"):
        select_finding([_kev_finding()], title="nonexistent")


def test_select_by_title_ambiguous_raises() -> None:
    with pytest.raises(ExplainError, match="matches 2 findings"):
        select_finding([_web_finding(), _web_finding()], title="cross")


def test_select_requires_exactly_one_selector() -> None:
    with pytest.raises(ExplainError, match="exactly one"):
        select_finding([_kev_finding()])
    with pytest.raises(ExplainError, match="exactly one"):
        select_finding([_kev_finding()], index=1, title="x")


# --------------------------------------------------------------------------- #
# explain_payload
# --------------------------------------------------------------------------- #
def test_payload_risk_breakdown_for_kev_cvss_finding() -> None:
    payload = explain_payload(_kev_finding())
    assert payload["risk"]["score"] == 98
    assert payload["risk"]["impact_source"] == "cvss"
    assert payload["risk"]["likelihood_source"] == "kev"
    assert payload["risk"]["likelihood"] == 1.0
    assert payload["kev"] is True


def test_payload_uses_severity_impact_and_no_likelihood_without_scores() -> None:
    finding = make_finding(
        source="zap", host="h", title="Header missing", severity=Severity.MEDIUM, plugin_id="1"
    )
    payload = explain_payload(finding)
    assert payload["risk"]["impact_source"] == "severity"
    assert payload["risk"]["likelihood_source"] == "none"
    assert payload["cvss"]["score"] is None


def test_payload_uses_epss_likelihood_when_not_kev() -> None:
    finding = make_finding(
        source="nmap",
        host="h",
        title="CVE",
        plugin_id="1",
        cve_ids=["CVE-2020-0001"],
        cvss_score=7.5,
        epss_score=0.3,
    )
    payload = explain_payload(finding)
    assert payload["risk"]["likelihood_source"] == "epss"
    assert payload["risk"]["likelihood"] == 0.3


def test_payload_carries_standards_and_ownership() -> None:
    payload = explain_payload(_web_finding())
    assert payload["owasp"] == [{"short": "A03", "title": "Injection"}]
    assert payload["cwe_top_25"] is True  # CWE-79 is a 2023 Top 25 weakness

    owned = explain_payload(_kev_finding())
    assert owned["owner"] == "platform-team"
    assert owned["tags"] == ["infrastructure"]
    assert owned["solution"].startswith("Upgrade")


def test_payload_risk_matches_the_finding_risk_score() -> None:
    # The breakdown's score is the same number the finding exposes -- single source.
    finding = _kev_finding()
    assert explain_payload(finding)["risk"]["score"] == finding.risk_score


# --------------------------------------------------------------------------- #
# render_explain
# --------------------------------------------------------------------------- #
def test_render_shows_the_risk_math() -> None:
    text = render_explain(_kev_finding())
    assert "Risk score: 98/100" in text
    assert "impact      = 0.98" in text
    assert "likelihood  = 1.00" in text
    assert "round(impact x (0.7 + 0.3 x likelihood) x 100) = 98" in text


def test_render_shows_context_sections() -> None:
    text = render_explain(_kev_finding())
    assert "Enrichment" in text
    assert "KEV    yes" in text
    assert "Classification" in text
    assert "Ownership" in text
    assert "platform-team" in text
    assert "Remediation" in text


def test_render_omits_ownership_when_absent() -> None:
    assert "Ownership" not in render_explain(_web_finding())


def test_render_covers_optional_branches() -> None:
    # Confidence set, no plugin_id, no CWEs, EPSS + percentile, owner but no tags,
    # and a solution with no references -- exercises the conditional render paths.
    finding = make_finding(
        source="zap",
        host="10.0.0.9",
        title="Some finding",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        cve_ids=["CVE-2020-1111"],
        epss_score=0.42,
        epss_percentile=0.9,
        cvss_score=6.5,
        solution="Apply the vendor patch.",
        metadata={"owner": "team-x"},
    )
    text = render_explain(finding)
    assert "high" in text  # confidence row
    assert "42.0%" in text  # EPSS shown as a percentage
    assert "percentile 90.0%" in text
    assert "Owner  team-x" in text
    assert "Tags" not in text  # no tags -> the tags line is omitted
    assert "Apply the vendor patch." in text
    assert "Plugin/alert" not in text  # no plugin id -> the row is omitted

    # A finding with references but no solution still lists the references.
    refs_only = make_finding(
        source="zap",
        host="h",
        title="t",
        plugin_id="1",
        references=["https://example.com/adv"],
    )
    assert "- https://example.com/adv" in render_explain(refs_only)


def test_render_is_deterministic() -> None:
    assert render_explain(_kev_finding()) == render_explain(_kev_finding())


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _findings_file(tmp_path: Path) -> Path:
    path = tmp_path / "findings.json"
    path.write_text(JsonReporter().render([_kev_finding(), _web_finding()]), encoding="utf-8")
    return path


def test_cli_explain_by_index_text(tmp_path: Path) -> None:
    result = runner.invoke(app, ["explain", "-i", str(_findings_file(tmp_path)), "--index", "1"])
    assert result.exit_code == 0
    assert "Risk score: 98/100" in result.stdout


def test_cli_explain_json(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["explain", "-i", str(_findings_file(tmp_path)), "--index", "1", "-f", "json"]
    )
    assert result.exit_code == 0
    assert json.loads(result.stdout)["risk"]["score"] == 98


def test_cli_explain_by_fingerprint_prefix(tmp_path: Path) -> None:
    prefix = _kev_finding().fingerprint[:12]
    result = runner.invoke(
        app, ["explain", "-i", str(_findings_file(tmp_path)), "--fingerprint", prefix]
    )
    assert result.exit_code == 0
    assert "CVE-2021-42013" in result.stdout


def test_cli_explain_no_selector_exits_two(tmp_path: Path) -> None:
    result = runner.invoke(app, ["explain", "-i", str(_findings_file(tmp_path))])
    assert result.exit_code == 2


def test_cli_explain_bad_format_exits_two(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["explain", "-i", str(_findings_file(tmp_path)), "--index", "1", "-f", "yaml"]
    )
    assert result.exit_code == 2
