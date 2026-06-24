"""Unit tests for the Typer CLI -- the ``report`` command wiring.

Drives the CLI in-process (no subprocess, no network) and asserts that a JSON
findings file renders into each supported format and that bad input fails cleanly.
"""

from pathlib import Path

from typer.testing import CliRunner

from vulnpipe.cli.main import app
from vulnpipe.core.models import Severity
from vulnpipe.processing.normalizer import make_finding
from vulnpipe.reporting.json_reporter import JsonReporter

runner = CliRunner()


def _write_report(tmp_path: Path) -> Path:
    findings = [
        make_finding(
            source="zap",
            host="app.lab.example.com",
            title="Cross Site Scripting (Reflected)",
            severity=Severity.HIGH,
            port=443,
            plugin_id="40012",
        )
    ]
    path = tmp_path / "findings.json"
    path.write_text(JsonReporter().render(findings), encoding="utf-8")
    return path


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
