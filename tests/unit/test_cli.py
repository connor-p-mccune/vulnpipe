"""Unit tests for the Typer CLI.

Drives the CLI in-process (no subprocess, no network, no real scanners). The
``scan`` tests stub the pipeline via ``run_pipeline`` so they exercise the
command's wiring -- argument parsing, report writing, and the gate exit code --
without scanning anything; ``report`` / ``diff`` / ``baseline`` run against real
findings JSON written to ``tmp_path``.
"""

import json
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Sequence
from datetime import date
from pathlib import Path

import httpx
import pytest
import respx
from typer.testing import CliRunner

from vulnpipe.ci.baseline import build_baseline, load_baseline, save_baseline
from vulnpipe.ci.differ import diff_findings
from vulnpipe.ci.gate import evaluate_gate
from vulnpipe.cli import main as cli_main
from vulnpipe.cli.main import app
from vulnpipe.core.models import Finding, Severity
from vulnpipe.core.orchestrator import PipelineResult
from vulnpipe.processing.normalizer import make_finding
from vulnpipe.reporting.json_reporter import JsonReporter
from vulnpipe.sbom import SbomError

runner = CliRunner()


def _f(title: str, *, severity: Severity = Severity.MEDIUM, host: str = "10.0.0.10") -> Finding:
    return make_finding(source="zap", host=host, title=title, severity=severity, plugin_id="1")


def _findings_file(tmp_path: Path, name: str, findings: Iterable[Finding]) -> Path:
    path = tmp_path / name
    path.write_text(JsonReporter().render(list(findings)), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #
def _write_report(tmp_path: Path) -> Path:
    return _findings_file(
        tmp_path,
        "findings.json",
        [
            make_finding(
                source="zap",
                host="app.lab.example.com",
                title="Cross Site Scripting (Reflected)",
                severity=Severity.HIGH,
                port=443,
                plugin_id="40012",
            )
        ],
    )


def test_schema_outputs_config_json_schema() -> None:
    result = runner.invoke(app, ["schema"])
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["type"] == "object"
    assert "scope" in document["properties"]
    assert "targets" in document["properties"]


def test_schema_report_kind_describes_the_envelope() -> None:
    result = runner.invoke(app, ["schema", "report"])
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["properties"]["schema_version"] == {"const": "1.0"}
    assert document["properties"]["findings"]["items"] == {"$ref": "#/$defs/Finding"}
    finding = document["$defs"]["Finding"]
    # Serialization mode: the computed fields are part of the contract.
    assert "fingerprint" in finding["properties"]
    assert "risk_score" in finding["properties"]


def test_schema_policy_kind_describes_gate_policy() -> None:
    result = runner.invoke(app, ["schema", "policy"])
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert "max_new" in document["properties"]
    assert "block_kev" in document["properties"]


def test_schema_unknown_kind_exits_two() -> None:
    result = runner.invoke(app, ["schema", "nonsense"])
    assert result.exit_code == 2


def test_schema_false_positives_kind_describes_the_allowlist() -> None:
    result = runner.invoke(app, ["schema", "false-positives"])
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert "fingerprints" in document["properties"]
    assert "min_confidence" in document["properties"]
    # The rule objects carry the risk-acceptance fields.
    assert "expires" in document["$defs"]["FingerprintRule"]["properties"]
    assert "reason" in document["$defs"]["PluginRule"]["properties"]


def test_plugins_reports_none_discovered() -> None:
    result = runner.invoke(app, ["plugins"])
    assert result.exit_code == 0
    assert "no third-party plugins discovered" in result.stdout
    assert "vulnpipe.scanners" in result.stdout  # points at the entry-point groups


# --------------------------------------------------------------------------- #
# merge
# --------------------------------------------------------------------------- #
def test_merge_dedupes_across_reports_and_writes_output(tmp_path: Path) -> None:
    shared = _f("Seen in both runs", severity=Severity.HIGH)
    first = _findings_file(tmp_path, "network.json", [shared, _f("Network only")])
    second = _findings_file(tmp_path, "sbom.json", [shared, _f("Supply chain only")])
    out = tmp_path / "merged.json"
    result = runner.invoke(app, ["merge", "-i", str(first), "-i", str(second), "-o", str(out)])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    titles = {finding["title"] for finding in payload["findings"]}
    assert titles == {"Seen in both runs", "Network only", "Supply chain only"}
    assert payload["summary"]["total"] == 3  # the duplicate collapsed
    # The written file matches what was emitted.
    assert json.loads(out.read_text(encoding="utf-8")) == payload


def test_merge_renders_any_report_format(tmp_path: Path) -> None:
    first = _findings_file(tmp_path, "a.json", [_f("Issue A")])
    result = runner.invoke(app, ["merge", "-i", str(first), "-f", "markdown"])
    assert result.exit_code == 0
    assert "Issue A" in result.stdout


def test_merge_unknown_format_exits_two(tmp_path: Path) -> None:
    first = _findings_file(tmp_path, "a.json", [_f("Issue A")])
    result = runner.invoke(app, ["merge", "-i", str(first), "-f", "docx"])
    assert result.exit_code == 2


def test_merge_unreadable_input_exits_two(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    result = runner.invoke(app, ["merge", "-i", str(bad)])
    assert result.exit_code == 2


# --------------------------------------------------------------------------- #
# convert (third-party scanner ingestion)
# --------------------------------------------------------------------------- #
_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_convert_trivy_to_findings_json(tmp_path: Path) -> None:
    out = tmp_path / "converted.json"
    result = runner.invoke(
        app,
        ["convert", "-i", str(_FIXTURES / "trivy_report.json"), "--from", "trivy", "-o", str(out)],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["total"] == 3
    assert any(f["source"] == "trivy" for f in payload["findings"])
    assert json.loads(out.read_text(encoding="utf-8")) == payload


def test_convert_grype_renders_markdown() -> None:
    grype = str(_FIXTURES / "grype_report.json")
    result = runner.invoke(app, ["convert", "-i", grype, "--from", "grype", "-f", "markdown"])
    assert result.exit_code == 0
    assert "CVE-2022-1271" in result.stdout


def test_convert_unknown_source_exits_two() -> None:
    result = runner.invoke(
        app, ["convert", "-i", str(_FIXTURES / "trivy_report.json"), "--from", "snyk"]
    )
    assert result.exit_code == 2


def test_convert_wrong_shape_exits_two(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"not": "a report"}', encoding="utf-8")
    result = runner.invoke(app, ["convert", "-i", str(bad), "--from", "trivy"])
    assert result.exit_code == 2


def test_report_json(tmp_path: Path) -> None:
    result = runner.invoke(app, ["report", "--input", str(_write_report(tmp_path)), "-f", "json"])
    assert result.exit_code == 0
    assert '"schema_version"' in result.stdout
    assert "Cross Site Scripting (Reflected)" in result.stdout


def test_report_html(tmp_path: Path) -> None:
    result = runner.invoke(app, ["report", "-i", str(_write_report(tmp_path)), "-f", "html"])
    assert result.exit_code == 0
    assert "<html" in result.stdout
    assert "<svg" in result.stdout


def test_report_sarif(tmp_path: Path) -> None:
    result = runner.invoke(app, ["report", "-i", str(_write_report(tmp_path)), "-f", "sarif"])
    assert result.exit_code == 0
    assert '"version": "2.1.0"' in result.stdout


def test_report_remediation_format(tmp_path: Path) -> None:
    result = runner.invoke(app, ["report", "-i", str(_write_report(tmp_path)), "-f", "remediation"])
    assert result.exit_code == 0
    assert result.stdout.startswith("# vulnpipe remediation plan")


def test_report_vex(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")  # keep the stamp deterministic
    findings = _findings_file(
        tmp_path,
        "findings.json",
        [
            make_finding(
                source="nmap",
                host="10.0.0.5",
                title="Apache httpd 2.4.49 path traversal",
                severity=Severity.CRITICAL,
                port=80,
                plugin_id="vulners",
                cve_ids=["CVE-2021-41773"],
                solution="Upgrade Apache httpd to 2.4.51 or later.",
            )
        ],
    )
    result = runner.invoke(app, ["report", "-i", str(findings), "-f", "vex"])
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert document["timestamp"] == "2023-11-14T22:13:20Z"
    statement = document["statements"][0]
    assert statement["vulnerability"]["name"] == "CVE-2021-41773"
    assert statement["status"] == "affected"


def test_report_markdown(tmp_path: Path) -> None:
    result = runner.invoke(app, ["report", "-i", str(_write_report(tmp_path)), "-f", "markdown"])
    assert result.exit_code == 0
    assert "# vulnpipe security report" in result.stdout
    assert "## Findings" in result.stdout
    assert "Cross Site Scripting (Reflected)" in result.stdout


def test_report_csv(tmp_path: Path) -> None:
    result = runner.invoke(app, ["report", "-i", str(_write_report(tmp_path)), "-f", "csv"])
    assert result.exit_code == 0
    assert result.stdout.startswith("fingerprint,severity,risk_score,")
    assert "Cross Site Scripting (Reflected)" in result.stdout


def test_report_prometheus(tmp_path: Path) -> None:
    result = runner.invoke(app, ["report", "-i", str(_write_report(tmp_path)), "-f", "prometheus"])
    assert result.exit_code == 0
    assert "# TYPE vulnpipe_findings_total gauge" in result.stdout
    assert 'vulnpipe_findings_total{severity="high"}' in result.stdout


def test_stats(tmp_path: Path) -> None:
    result = runner.invoke(app, ["stats", "-i", str(_write_report(tmp_path))])
    assert result.exit_code == 0
    assert "findings across" in result.stdout
    assert "By severity" in result.stdout
    assert "Top 10 by risk" in result.stdout


def test_stats_json(tmp_path: Path) -> None:
    result = runner.invoke(app, ["stats", "-i", str(_write_report(tmp_path)), "-f", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["total"] == 1
    assert payload["by_severity"]["high"] == 1
    assert "remediation" in payload


def test_stats_unknown_format_exits_two(tmp_path: Path) -> None:
    result = runner.invoke(app, ["stats", "-i", str(_write_report(tmp_path)), "-f", "xml"])
    assert result.exit_code == 2


def test_stats_invalid_input_exits_nonzero(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    result = runner.invoke(app, ["stats", "-i", str(bad)])
    assert result.exit_code == 2


def test_remediate_text_lists_a_plan(tmp_path: Path) -> None:
    result = runner.invoke(app, ["remediate", "-i", str(_write_report(tmp_path))])
    assert result.exit_code == 0
    assert "vulnpipe remediation plan" in result.stdout
    assert "Recommended actions" in result.stdout


def test_remediate_json_emits_actions(tmp_path: Path) -> None:
    result = runner.invoke(app, ["remediate", "-i", str(_write_report(tmp_path)), "-f", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["actions"] >= 1
    assert payload["actions"][0]["rank"] == 1


def test_remediate_markdown_and_top(tmp_path: Path) -> None:
    findings = _findings_file(
        tmp_path, "many.json", [_f("A", host="a"), _f("B", host="b"), _f("C", host="c")]
    )
    result = runner.invoke(app, ["remediate", "-i", str(findings), "-f", "markdown", "--top", "1"])
    assert result.exit_code == 0
    assert result.stdout.startswith("# vulnpipe remediation plan")
    assert "more action(s)" in result.stdout


def test_remediate_rejects_unknown_format(tmp_path: Path) -> None:
    result = runner.invoke(app, ["remediate", "-i", str(_write_report(tmp_path)), "-f", "xml"])
    assert result.exit_code == 2


def test_badge_renders_svg_to_stdout(tmp_path: Path) -> None:
    result = runner.invoke(app, ["badge", "-i", str(_write_report(tmp_path))])
    assert result.exit_code == 0
    assert result.stdout.startswith("<svg")
    assert "1 high" in result.stdout


def test_badge_writes_file_with_custom_label(tmp_path: Path) -> None:
    out = tmp_path / "badge.svg"
    result = runner.invoke(
        app,
        ["badge", "-i", str(_write_report(tmp_path)), "-o", str(out), "--label", "security"],
    )
    assert result.exit_code == 0
    svg = out.read_text(encoding="utf-8")
    assert "security" in svg and svg.startswith("<svg")


def test_badge_invalid_input_exits_two(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    result = runner.invoke(app, ["badge", "-i", str(bad)])
    assert result.exit_code == 2


# --------------------------------------------------------------------------- #
# notify
# --------------------------------------------------------------------------- #
_WEBHOOK = "https://hooks.example.com/services/T/B/X"


@respx.mock
def test_notify_posts_summary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VULNPIPE_WEBHOOK_URL", _WEBHOOK)
    route = respx.post(_WEBHOOK).mock(return_value=httpx.Response(200))
    result = runner.invoke(app, ["notify", "-i", str(_write_report(tmp_path))])
    assert result.exit_code == 0
    assert route.called


def test_notify_missing_url_exits_two(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VULNPIPE_WEBHOOK_URL", raising=False)
    result = runner.invoke(app, ["notify", "-i", str(_write_report(tmp_path))])
    assert result.exit_code == 2


@respx.mock
def test_notify_webhook_failure_exits_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VULNPIPE_WEBHOOK_URL", _WEBHOOK)
    respx.post(_WEBHOOK).mock(return_value=httpx.Response(500))
    result = runner.invoke(app, ["notify", "-i", str(_write_report(tmp_path))])
    assert result.exit_code == 1


def test_trend_text(tmp_path: Path) -> None:
    a = _findings_file(tmp_path, "2026-06-01.json", [_f("RCE", severity=Severity.HIGH)])
    b = _findings_file(
        tmp_path,
        "2026-06-15.json",
        [_f("RCE", severity=Severity.HIGH), _f("SQLi", severity=Severity.CRITICAL)],
    )
    result = runner.invoke(app, ["trend", str(a), str(b)])
    assert result.exit_code == 0
    assert "risk trend: worsening" in result.stdout
    assert "2026-06-01" in result.stdout and "2026-06-15" in result.stdout


def test_trend_json(tmp_path: Path) -> None:
    a = _findings_file(tmp_path, "s1.json", [_f("RCE", severity=Severity.HIGH)])
    result = runner.invoke(app, ["trend", "--format", "json", str(a)])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["scans"][0]["label"] == "s1"


def test_trend_html(tmp_path: Path) -> None:
    a = _findings_file(tmp_path, "s1.json", [_f("RCE", severity=Severity.HIGH)])
    b = _findings_file(
        tmp_path, "s2.json", [_f("RCE", severity=Severity.HIGH), _f("SQLi", severity=Severity.HIGH)]
    )
    result = runner.invoke(app, ["trend", "--format", "html", str(a), str(b)])
    assert result.exit_code == 0
    assert result.stdout.lstrip().startswith("<!DOCTYPE html>")
    assert "<svg" in result.stdout and "Risk trend:" in result.stdout


def test_diff_markdown_format(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    save_baseline(build_baseline([_f("kept")]), baseline_path)
    current = _findings_file(
        tmp_path, "current.json", [_f("kept"), _f("new-high", severity=Severity.HIGH)]
    )
    result = runner.invoke(
        app, ["diff", "--baseline", str(baseline_path), "--current", str(current), "-f", "markdown"]
    )
    assert result.exit_code == 0
    assert "## vulnpipe scan delta" in result.stdout
    assert "### New findings" in result.stdout
    assert "new-high" in result.stdout


def test_diff_html_format(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    save_baseline(build_baseline([_f("kept")]), baseline_path)
    current = _findings_file(
        tmp_path, "current.json", [_f("kept"), _f("new-high", severity=Severity.HIGH)]
    )
    result = runner.invoke(
        app, ["diff", "--baseline", str(baseline_path), "--current", str(current), "-f", "html"]
    )
    assert result.exit_code == 0
    assert result.stdout.startswith("<!DOCTYPE html>")
    assert "<h2>New findings</h2>" in result.stdout
    assert "new-high" in result.stdout


def test_diff_unknown_format_exits_two(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    save_baseline(build_baseline([]), baseline_path)
    current = _findings_file(tmp_path, "current.json", [])
    result = runner.invoke(
        app, ["diff", "--baseline", str(baseline_path), "--current", str(current), "-f", "xml"]
    )
    assert result.exit_code == 2


def test_trend_unknown_format_exits_nonzero(tmp_path: Path) -> None:
    a = _findings_file(tmp_path, "s1.json", [_f("RCE", severity=Severity.HIGH)])
    result = runner.invoke(app, ["trend", "--format", "xml", str(a)])
    assert result.exit_code == 2


def test_trend_missing_file_exits_nonzero(tmp_path: Path) -> None:
    result = runner.invoke(app, ["trend", str(tmp_path / "nope.json")])
    assert result.exit_code == 2


# --------------------------------------------------------------------------- #
# validate
# --------------------------------------------------------------------------- #
def test_validate_in_scope_config_passes(tmp_path: Path) -> None:
    result = runner.invoke(app, ["validate", "-c", str(_write_config(tmp_path))])
    assert result.exit_code == 0
    assert "Scan plan" in result.stdout
    assert "10.0.0.10" in result.stdout
    assert "OK:" in result.stdout


def test_validate_out_of_scope_config_exits_one(tmp_path: Path) -> None:
    cfg = tmp_path / "targets.yaml"
    cfg.write_text(
        'scope:\n  hosts: ["10.0.0.0/24"]\ntargets:\n  - host: "192.168.1.1"\n',
        encoding="utf-8",
    )
    result = runner.invoke(app, ["validate", "-c", str(cfg)])
    assert result.exit_code == 1
    assert "out of scope" in result.stdout


def test_validate_bad_config_exits_two(tmp_path: Path) -> None:
    cfg = tmp_path / "targets.yaml"
    cfg.write_text("scope: {}\n", encoding="utf-8")  # no targets -> invalid schema
    result = runner.invoke(app, ["validate", "-c", str(cfg)])
    assert result.exit_code == 2


def test_report_unknown_format_exits_nonzero(tmp_path: Path) -> None:
    result = runner.invoke(app, ["report", "-i", str(_write_report(tmp_path)), "-f", "pdf"])
    assert result.exit_code == 2


def test_report_invalid_json_exits_nonzero(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    result = runner.invoke(app, ["report", "-i", str(bad), "-f", "json"])
    assert result.exit_code == 2


# --------------------------------------------------------------------------- #
# sbom (standalone supply-chain analysis; pipeline stubbed)
# --------------------------------------------------------------------------- #
def _write_cyclonedx(tmp_path: Path) -> Path:
    path = tmp_path / "sbom.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [
                    {"name": "requests", "version": "2.19.0", "purl": "pkg:pypi/requests@2.19.0"}
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _sbom_finding() -> Finding:
    return make_finding(
        source="sbom",
        host="acme-webapp",
        title="GHSA-x84v-xcm2-53pg: requests 2.19.0",
        severity=Severity.HIGH,
        plugin_id="GHSA-x84v-xcm2-53pg",
        cve_ids=["CVE-2018-18074"],
        cvss_score=7.5,
    )


def test_sbom_renders_findings_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_main, "run_sbom_pipeline", lambda *a, **k: [_sbom_finding()])
    result = runner.invoke(app, ["sbom", "-i", str(_write_cyclonedx(tmp_path))])
    assert result.exit_code == 0
    assert '"schema_version"' in result.stdout
    assert "GHSA-x84v-xcm2-53pg: requests 2.19.0" in result.stdout


def test_sbom_writes_output_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_main, "run_sbom_pipeline", lambda *a, **k: [_sbom_finding()])
    out = tmp_path / "results"
    result = runner.invoke(
        app, ["sbom", "-i", str(_write_cyclonedx(tmp_path)), "-o", str(out), "-f", "markdown"]
    )
    assert result.exit_code == 0
    assert (out / "sbom.json").is_file()
    assert "# vulnpipe security report" in result.stdout  # markdown to stdout


def test_sbom_passes_no_enrich_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def _capture(_path: object, **kwargs: object) -> list[Finding]:
        captured.update(kwargs)
        return []

    monkeypatch.setattr(cli_main, "run_sbom_pipeline", _capture)
    result = runner.invoke(app, ["sbom", "-i", str(_write_cyclonedx(tmp_path)), "--no-enrich"])
    assert result.exit_code == 0
    assert captured["enrich"] is False


def test_sbom_unknown_format_exits_two(tmp_path: Path) -> None:
    result = runner.invoke(app, ["sbom", "-i", str(_write_cyclonedx(tmp_path)), "-f", "pdf"])
    assert result.exit_code == 2


def test_sbom_bad_file_exits_two(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_a: object, **_k: object) -> list[Finding]:
        raise SbomError("Unsupported SBOM format: 'SPDX'")

    monkeypatch.setattr(cli_main, "run_sbom_pipeline", _boom)
    result = runner.invoke(app, ["sbom", "-i", str(_write_cyclonedx(tmp_path))])
    assert result.exit_code == 2


# --------------------------------------------------------------------------- #
# gate (policy evaluation without rescanning)
# --------------------------------------------------------------------------- #
def _write_policy(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_gate_passes_when_within_policy(tmp_path: Path) -> None:
    current = _findings_file(tmp_path, "current.json", [_f("Low issue", severity=Severity.LOW)])
    policy = _write_policy(tmp_path, "max_new:\n  critical: 0\n  high: 0\n")
    result = runner.invoke(app, ["gate", "--current", str(current), "--policy", str(policy)])
    assert result.exit_code == 0
    assert "gate passed" in result.stdout


def test_gate_fails_on_policy_violation_with_details(tmp_path: Path) -> None:
    current = _findings_file(tmp_path, "current.json", [_f("RCE", severity=Severity.HIGH)])
    policy = _write_policy(tmp_path, "max_new:\n  high: 0\n")
    result = runner.invoke(app, ["gate", "--current", str(current), "--policy", str(policy)])
    assert result.exit_code == 1
    assert "gate failed" in result.stdout
    assert "exceed the budget of 0" in result.stdout
    assert "RCE" in result.stdout


def test_gate_baselined_findings_pass(tmp_path: Path) -> None:
    finding = _f("Known high", severity=Severity.HIGH)
    current = _findings_file(tmp_path, "current.json", [finding])
    baseline_path = tmp_path / "baseline.json"
    save_baseline(build_baseline([finding]), baseline_path)
    policy = _write_policy(tmp_path, "max_new:\n  high: 0\n")
    result = runner.invoke(
        app,
        [
            "gate",
            "--current",
            str(current),
            "--baseline",
            str(baseline_path),
            "--policy",
            str(policy),
        ],
    )
    assert result.exit_code == 0


def test_gate_defaults_to_severity_threshold(tmp_path: Path) -> None:
    current = _findings_file(tmp_path, "current.json", [_f("RCE", severity=Severity.HIGH)])
    failing = runner.invoke(app, ["gate", "--current", str(current)])
    assert failing.exit_code == 1  # default threshold is high
    passing = runner.invoke(app, ["gate", "--current", str(current), "--gate-severity", "critical"])
    assert passing.exit_code == 0


def test_gate_json_output(tmp_path: Path) -> None:
    current = _findings_file(tmp_path, "current.json", [_f("RCE", severity=Severity.HIGH)])
    result = runner.invoke(app, ["gate", "--current", str(current), "--format", "json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["passed"] is False
    assert payload["violations"][0]["rule"] == "max_new[high]"


def test_gate_unknown_format_exits_two(tmp_path: Path) -> None:
    current = _findings_file(tmp_path, "current.json", [])
    result = runner.invoke(app, ["gate", "--current", str(current), "--format", "xml"])
    assert result.exit_code == 2


def test_gate_bad_policy_exits_two(tmp_path: Path) -> None:
    current = _findings_file(tmp_path, "current.json", [])
    policy = _write_policy(tmp_path, "unknown_rule: 1\n")
    result = runner.invoke(app, ["gate", "--current", str(current), "--policy", str(policy)])
    assert result.exit_code == 2


# --------------------------------------------------------------------------- #
# scan (pipeline stubbed via run_pipeline)
# --------------------------------------------------------------------------- #
def _write_config(tmp_path: Path, *, target_host: str = "10.0.0.10") -> Path:
    cfg = tmp_path / "targets.yaml"
    cfg.write_text(
        'scope:\n  hosts: ["10.0.0.0/24"]\n'
        f'targets:\n  - host: "{target_host}"\n'
        "enrichment:\n  nvd_enabled: false\n  epss_enabled: false\n",
        encoding="utf-8",
    )
    return cfg


def _result(
    findings: Sequence[Finding], baseline_findings: Sequence[Finding] = ()
) -> PipelineResult:
    diff = diff_findings(list(findings), build_baseline(list(baseline_findings)))
    return PipelineResult(findings=tuple(findings), diff=diff, gate=evaluate_gate(diff))


def _stub_pipeline(monkeypatch: pytest.MonkeyPatch, result: PipelineResult) -> None:
    monkeypatch.setattr(cli_main, "run_pipeline", lambda *args, **kwargs: result)


def test_scan_writes_reports_and_passes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_pipeline(monkeypatch, _result([_f("Low issue", severity=Severity.LOW)]))
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "scan",
            "-c",
            str(_write_config(tmp_path)),
            "--authorized",
            "-o",
            str(out),
            "--sarif",
            str(out / "report.sarif"),
            "--junit",
            str(out / "junit.xml"),
            "--html",
            str(out / "report.html"),
            "--markdown",
            str(out / "report.md"),
            "--vex",
            str(out / "report.vex.json"),
            "--remediation",
            str(out / "remediation.md"),
        ],
    )
    assert result.exit_code == 0
    assert (out / "latest.json").is_file()
    assert (out / "report.sarif").is_file()
    assert (out / "junit.xml").is_file()
    assert (out / "report.html").is_file()
    assert (out / "report.md").is_file()
    assert "vulnpipe remediation plan" in (out / "remediation.md").read_text(encoding="utf-8")
    vex_doc = json.loads((out / "report.vex.json").read_text(encoding="utf-8"))
    assert vex_doc["@context"] == "https://openvex.dev/ns/v0.2.0"


def test_scan_accepts_gate_risk_score(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def _capture(*_args: object, **kwargs: object) -> PipelineResult:
        captured.update(kwargs)
        return _result([_f("Low issue", severity=Severity.LOW)])

    monkeypatch.setattr(cli_main, "run_pipeline", _capture)
    result = runner.invoke(
        app,
        ["scan", "-c", str(_write_config(tmp_path)), "--authorized", "--gate-risk-score", "80"],
    )
    assert result.exit_code == 0
    assert captured["gate_min_risk_score"] == 80


def test_scan_policy_overrides_severity_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A new High fails the default gate, but a permissive policy allows it.
    _stub_pipeline(monkeypatch, _result([_f("RCE", severity=Severity.HIGH)]))
    policy = tmp_path / "policy.yaml"
    policy.write_text("max_new:\n  high: 5\n", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "scan",
            "-c",
            str(_write_config(tmp_path)),
            "--authorized",
            "-o",
            str(tmp_path / "out"),
            "--policy",
            str(policy),
        ],
    )
    assert result.exit_code == 0


def test_scan_policy_violation_fails_and_writes_junit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A new Medium passes the default severity gate but violates the policy budget.
    _stub_pipeline(monkeypatch, _result([_f("Sneaky medium", severity=Severity.MEDIUM)]))
    policy = tmp_path / "policy.yaml"
    policy.write_text("max_new:\n  medium: 0\n", encoding="utf-8")
    junit_path = tmp_path / "out" / "junit.xml"
    result = runner.invoke(
        app,
        [
            "scan",
            "-c",
            str(_write_config(tmp_path)),
            "--authorized",
            "-o",
            str(tmp_path / "out"),
            "--policy",
            str(policy),
            "--junit",
            str(junit_path),
        ],
    )
    assert result.exit_code == 1
    xml = junit_path.read_text(encoding="utf-8")
    assert 'failures="1"' in xml
    # The policy criteria land in the failure body (XML-escaped in the raw text).
    failure = ET.fromstring(xml).find("./testsuite/testcase/failure")
    assert failure is not None and failure.text is not None
    assert "new medium <= 0" in failure.text


def test_scan_invalid_policy_exits_two(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_pipeline(monkeypatch, _result([]))
    policy = tmp_path / "policy.yaml"
    policy.write_text("bogus: true\n", encoding="utf-8")
    result = runner.invoke(
        app,
        ["scan", "-c", str(_write_config(tmp_path)), "--authorized", "--policy", str(policy)],
    )
    assert result.exit_code == 2


def test_scan_gate_failure_exits_nonzero(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_pipeline(monkeypatch, _result([_f("RCE", severity=Severity.HIGH)]))
    out = tmp_path / "out"
    result = runner.invoke(
        app, ["scan", "-c", str(_write_config(tmp_path)), "--authorized", "-o", str(out)]
    )
    assert result.exit_code == 1
    # Reports are written before the gate exit, so CI can still upload them.
    assert (out / "latest.json").is_file()


def test_scan_no_gate_exits_zero_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_pipeline(monkeypatch, _result([_f("RCE", severity=Severity.HIGH)]))
    result = runner.invoke(
        app,
        [
            "scan",
            "-c",
            str(_write_config(tmp_path)),
            "--authorized",
            "-o",
            str(tmp_path / "out"),
            "--no-gate",
        ],
    )
    assert result.exit_code == 0


def test_scan_requires_authorized_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: object, **_kwargs: object) -> PipelineResult:
        raise AssertionError("run_pipeline must not run without --authorized")

    monkeypatch.setattr(cli_main, "run_pipeline", boom)
    result = runner.invoke(
        app, ["scan", "-c", str(_write_config(tmp_path)), "-o", str(tmp_path / "out")]
    )
    assert result.exit_code == 2


def test_scan_out_of_scope_exits_2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_pipeline(monkeypatch, _result([]))
    cfg = _write_config(tmp_path, target_host="203.0.113.5")  # outside the scope allowlist
    result = runner.invoke(
        app, ["scan", "-c", str(cfg), "--authorized", "-o", str(tmp_path / "out")]
    )
    assert result.exit_code == 2


def test_scan_invalid_config_exits_2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_pipeline(monkeypatch, _result([]))
    bad = tmp_path / "bad.yaml"
    bad.write_text("scope: {}\ntargets: []\n", encoding="utf-8")  # empty targets -> invalid
    result = runner.invoke(
        app, ["scan", "-c", str(bad), "--authorized", "-o", str(tmp_path / "out")]
    )
    assert result.exit_code == 2


# --------------------------------------------------------------------------- #
# diff
# --------------------------------------------------------------------------- #
def test_diff_text(tmp_path: Path) -> None:
    kept, gone, fresh = _f("kept"), _f("removed"), _f("introduced")
    base = _findings_file(tmp_path, "base.json", [kept, gone])
    cur = _findings_file(tmp_path, "cur.json", [kept, fresh])
    result = runner.invoke(app, ["diff", "--baseline", str(base), "--current", str(cur)])
    assert result.exit_code == 0
    assert "new:" in result.stdout
    assert "+ [medium] introduced" in result.stdout
    assert "- [medium] removed" in result.stdout


def test_diff_json(tmp_path: Path) -> None:
    kept, fresh = _f("kept"), _f("introduced")
    base = _findings_file(tmp_path, "base.json", [kept])
    cur = _findings_file(tmp_path, "cur.json", [kept, fresh])
    result = runner.invoke(
        app, ["diff", "--baseline", str(base), "--current", str(cur), "-f", "json"]
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"] == {"new": 1, "persisting": 1, "resolved": 0}


def test_diff_accepts_a_baseline_file(tmp_path: Path) -> None:
    kept = _f("kept")
    bpath = tmp_path / "baseline.json"
    save_baseline(build_baseline([kept]), bpath)
    cur = _findings_file(tmp_path, "cur.json", [kept, _f("introduced")])
    result = runner.invoke(app, ["diff", "--baseline", str(bpath), "--current", str(cur)])
    assert result.exit_code == 0
    assert "+ [medium] introduced" in result.stdout


def test_diff_unknown_format_exits_2(tmp_path: Path) -> None:
    f = _findings_file(tmp_path, "f.json", [_f("a")])
    result = runner.invoke(app, ["diff", "--baseline", str(f), "--current", str(f), "-f", "xml"])
    assert result.exit_code == 2


def test_diff_invalid_current_exits_2(tmp_path: Path) -> None:
    base = _findings_file(tmp_path, "base.json", [_f("a")])
    bad = tmp_path / "cur.json"
    bad.write_text("{ not json", encoding="utf-8")
    result = runner.invoke(app, ["diff", "--baseline", str(base), "--current", str(bad)])
    assert result.exit_code == 2


# --------------------------------------------------------------------------- #
# version
# --------------------------------------------------------------------------- #
def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0


# --------------------------------------------------------------------------- #
# baseline
# --------------------------------------------------------------------------- #
def test_baseline_create(tmp_path: Path) -> None:
    src = _findings_file(tmp_path, "f.json", [_f("a"), _f("b")])
    out = tmp_path / "baseline.json"
    result = runner.invoke(app, ["baseline", "-i", str(src), "-o", str(out)])
    assert result.exit_code == 0
    assert len(load_baseline(out).entries) == 2


def test_baseline_update_merges(tmp_path: Path) -> None:
    out = tmp_path / "baseline.json"
    save_baseline(build_baseline([_f("a")]), out)
    src = _findings_file(tmp_path, "f.json", [_f("a"), _f("b")])
    result = runner.invoke(app, ["baseline", "-i", str(src), "-o", str(out), "--update"])
    assert result.exit_code == 0
    assert len(load_baseline(out).entries) == 2


def test_baseline_invalid_input_exits_2(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    result = runner.invoke(app, ["baseline", "-i", str(bad), "-o", str(tmp_path / "b.json")])
    assert result.exit_code == 2


def test_baseline_track_age_records_first_seen(tmp_path: Path) -> None:
    src = _findings_file(tmp_path, "f.json", [_f("RCE", severity=Severity.HIGH)])
    out = tmp_path / "baseline.json"
    result = runner.invoke(app, ["baseline", "-i", str(src), "-o", str(out), "--track-age"])
    assert result.exit_code == 0
    assert "first_seen" in out.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# sla
# --------------------------------------------------------------------------- #
def _aged_baseline(tmp_path: Path, finding: Finding, first_seen: date) -> Path:
    path = tmp_path / "aged-baseline.json"
    save_baseline(build_baseline([finding], first_seen=first_seen), path)
    return path


def test_sla_flags_overdue_finding(tmp_path: Path) -> None:
    finding = _f("CVE-2021-42013", severity=Severity.CRITICAL)
    base = _aged_baseline(tmp_path, finding, date(2020, 1, 1))
    current = _findings_file(tmp_path, "cur.json", [finding])
    result = runner.invoke(
        app,
        [
            "sla",
            "--current",
            str(current),
            "--baseline",
            str(base),
            "--critical-days",
            "7",
            "--as-of",
            "2020-02-01",
        ],
    )
    assert result.exit_code == 1
    assert "SLA breached" in result.stdout


def test_sla_passes_within_deadline_json(tmp_path: Path) -> None:
    finding = _f("CVE-2021-42013", severity=Severity.CRITICAL)
    base = _aged_baseline(tmp_path, finding, date(2020, 1, 1))
    current = _findings_file(tmp_path, "cur.json", [finding])
    result = runner.invoke(
        app,
        [
            "sla",
            "--current",
            str(current),
            "--baseline",
            str(base),
            "--critical-days",
            "365",
            "--as-of",
            "2020-02-01",
            "-f",
            "json",
        ],
    )
    assert result.exit_code == 0
    assert json.loads(result.stdout)["passed"] is True


def test_sla_invalid_as_of_exits_two(tmp_path: Path) -> None:
    finding = _f("CVE", severity=Severity.CRITICAL)
    base = _aged_baseline(tmp_path, finding, date(2020, 1, 1))
    current = _findings_file(tmp_path, "cur.json", [finding])
    result = runner.invoke(
        app,
        ["sla", "--current", str(current), "--baseline", str(base), "--as-of", "not-a-date"],
    )
    assert result.exit_code == 2


def test_schema_sla_kind_describes_the_policy() -> None:
    result = runner.invoke(app, ["schema", "sla"])
    assert result.exit_code == 0
    assert "max_age_days" in result.stdout
