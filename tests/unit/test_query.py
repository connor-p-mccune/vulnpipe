"""Unit tests for the composable findings query (`filter`)."""

import json
from pathlib import Path

from typer.testing import CliRunner

from vulnpipe.cli.main import app
from vulnpipe.core.models import Finding, Severity
from vulnpipe.processing.normalizer import make_finding
from vulnpipe.processing.query import FindingQuery, apply_query, build_query, matches
from vulnpipe.reporting.json_reporter import JsonReporter

runner = CliRunner()


def _crit_kev() -> Finding:
    return make_finding(
        source="nmap",
        host="10.0.0.5",
        title="CVE-2021-42013",
        severity=Severity.CRITICAL,
        plugin_id="vulners",
        cve_ids=["CVE-2021-42013"],
        cvss_score=9.8,
        kev=True,
        metadata={"owner": "team-web", "tags": ["pci"]},
    )


def _high() -> Finding:
    return make_finding(
        source="zap",
        host="app.lab.example.com",
        title="Cross Site Scripting",
        severity=Severity.HIGH,
        plugin_id="40012",
        metadata={"owner": "team-web"},
    )


def _med() -> Finding:
    return make_finding(
        source="zap",
        host="10.0.0.6",
        title="Vulnerable JS Library",
        severity=Severity.MEDIUM,
        plugin_id="10003",
        metadata={"owner": "team-infra"},
    )


def _low_unassigned() -> Finding:
    return make_finding(
        source="nmap", host="10.0.0.7", title="Open port", severity=Severity.LOW, plugin_id="p"
    )


def _all() -> list[Finding]:
    return [_crit_kev(), _high(), _med(), _low_unassigned()]


def _titles(findings: list[Finding]) -> list[str]:
    return [f.title for f in findings]


# --------------------------------------------------------------------------- #
# Individual predicates
# --------------------------------------------------------------------------- #
def test_empty_query_keeps_everything_in_order() -> None:
    assert FindingQuery().is_empty is True
    assert apply_query(_all(), FindingQuery()) == _all()


def test_min_severity() -> None:
    kept = apply_query(_all(), build_query(min_severity=Severity.HIGH))
    assert _titles(kept) == ["CVE-2021-42013", "Cross Site Scripting"]


def test_min_risk() -> None:
    kept = apply_query(_all(), build_query(min_risk=50))
    assert all(f.risk_score >= 50 for f in kept)
    assert "Vulnerable JS Library" not in _titles(kept)


def test_kev_only() -> None:
    assert _titles(apply_query(_all(), build_query(kev_only=True))) == ["CVE-2021-42013"]


def test_owner_filter() -> None:
    kept = apply_query(_all(), build_query(owners=["team-web"]))
    assert _titles(kept) == ["CVE-2021-42013", "Cross Site Scripting"]


def test_unassigned_filter() -> None:
    assert _titles(apply_query(_all(), build_query(unassigned=True))) == ["Open port"]


def test_owner_or_unassigned_combine() -> None:
    kept = apply_query(_all(), build_query(owners=["team-infra"], unassigned=True))
    assert _titles(kept) == ["Vulnerable JS Library", "Open port"]


def test_source_filter_is_case_insensitive() -> None:
    kept = apply_query(_all(), build_query(sources=["ZAP"]))
    assert _titles(kept) == ["Cross Site Scripting", "Vulnerable JS Library"]


def test_host_substring_filter() -> None:
    kept = apply_query(_all(), build_query(hosts=["10.0.0"]))
    assert _titles(kept) == ["CVE-2021-42013", "Vulnerable JS Library", "Open port"]


def test_tag_filter() -> None:
    assert _titles(apply_query(_all(), build_query(tags=["pci"]))) == ["CVE-2021-42013"]


def test_cve_filter_is_case_insensitive() -> None:
    kept = apply_query(_all(), build_query(cves=["cve-2021-42013"]))
    assert _titles(kept) == ["CVE-2021-42013"]


def test_criteria_and_together() -> None:
    # severity >= high AND source zap -> only the XSS finding.
    kept = apply_query(_all(), build_query(min_severity=Severity.HIGH, sources=["zap"]))
    assert _titles(kept) == ["Cross Site Scripting"]


def test_repeated_criterion_is_or() -> None:
    kept = apply_query(_all(), build_query(sources=["nmap", "zap"]))
    assert len(kept) == 4  # either source keeps all


def test_matches_single_finding() -> None:
    assert matches(_crit_kev(), build_query(kev_only=True)) is True
    assert matches(_high(), build_query(kev_only=True)) is False


def test_build_query_normalizes_none_to_empty() -> None:
    query = build_query(owners=None, sources=None)
    assert query.owners == ()
    assert query.sources == ()
    assert query.is_empty is True


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _findings_file(tmp_path: Path) -> Path:
    path = tmp_path / "findings.json"
    path.write_text(JsonReporter().render(_all()), encoding="utf-8")
    return path


def test_cli_filter_by_owner_and_severity(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "filter",
            "-i",
            str(_findings_file(tmp_path)),
            "--owner",
            "team-web",
            "--severity",
            "high",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["total"] == 2


def test_cli_filter_repeated_owner(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "filter",
            "-i",
            str(_findings_file(tmp_path)),
            "--owner",
            "team-web",
            "--owner",
            "team-infra",
        ],
    )
    assert result.exit_code == 0
    assert json.loads(result.stdout)["summary"]["total"] == 3


def test_cli_filter_writes_output_and_renders_format(tmp_path: Path) -> None:
    out = tmp_path / "filtered.json"
    result = runner.invoke(
        app,
        ["filter", "-i", str(_findings_file(tmp_path)), "--kev", "-o", str(out), "-f", "markdown"],
    )
    assert result.exit_code == 0
    assert "security report" in result.stdout  # markdown to stdout
    written = json.loads(out.read_text(encoding="utf-8"))  # JSON to the output file
    assert written["summary"]["total"] == 1


def test_cli_filter_unknown_format_exits_two(tmp_path: Path) -> None:
    result = runner.invoke(app, ["filter", "-i", str(_findings_file(tmp_path)), "-f", "nonsense"])
    assert result.exit_code == 2


def test_cli_filter_bad_input_exits_two(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    result = runner.invoke(app, ["filter", "-i", str(bad)])
    assert result.exit_code == 2
