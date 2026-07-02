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


def test_stats_invalid_input_exits_nonzero(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    result = runner.invoke(app, ["stats", "-i", str(bad)])
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
        ],
    )
    assert result.exit_code == 0
    assert (out / "latest.json").is_file()
    assert (out / "report.sarif").is_file()
    assert (out / "junit.xml").is_file()
    assert (out / "report.html").is_file()
    assert (out / "report.md").is_file()


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
