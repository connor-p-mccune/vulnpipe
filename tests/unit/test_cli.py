"""Unit tests for the Typer CLI.

Drives the CLI in-process (no subprocess, no network, no real scanners). The
``scan`` tests stub the pipeline via ``run_pipeline`` so they exercise the
command's wiring -- argument parsing, report writing, and the gate exit code --
without scanning anything; ``report`` / ``diff`` / ``baseline`` run against real
findings JSON written to ``tmp_path``.
"""

import json
from collections.abc import Iterable, Sequence
from pathlib import Path

import pytest
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


def test_report_unknown_format_exits_nonzero(tmp_path: Path) -> None:
    result = runner.invoke(app, ["report", "-i", str(_write_report(tmp_path)), "-f", "pdf"])
    assert result.exit_code == 2


def test_report_invalid_json_exits_nonzero(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    result = runner.invoke(app, ["report", "-i", str(bad), "-f", "json"])
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
        ],
    )
    assert result.exit_code == 0
    assert (out / "latest.json").is_file()
    assert (out / "report.sarif").is_file()
    assert (out / "junit.xml").is_file()
    assert (out / "report.html").is_file()


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
