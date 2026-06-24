"""Integration test: full pipeline wiring driven through the CLI.

Marked ``integration`` (skipped in a plain ``pytest`` run). It stubs the Nmap and
ZAP scanners at the registry boundary, then drives the real ``scan`` command
end-to-end -- discovery, enrichment (disabled), dedup, false-positive filtering,
prioritization, baseline diff, gate, and report writing -- asserting the artifacts
and the gate exit code. No real scanners, tools, or network are used.
"""

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vulnpipe.cli.main import app
from vulnpipe.core import orchestrator
from vulnpipe.core.models import Finding, Severity
from vulnpipe.processing.normalizer import make_finding
from vulnpipe.scanners.base import BaseScanner

pytestmark = pytest.mark.integration
runner = CliRunner()


def _nmap_findings() -> list[Finding]:
    return [
        make_finding(
            source="nmap",
            host="10.0.0.10",
            title="Open port 443/tcp",
            severity=Severity.INFORMATIONAL,
            port=443,
            metadata={"service": "https"},
        ),
        make_finding(
            source="nmap",
            host="10.0.0.10",
            title="CVE-2021-44228",
            severity=Severity.CRITICAL,
            port=443,
            plugin_id="vulners",
            cve_ids=["CVE-2021-44228"],
            cvss_score=10.0,
        ),
    ]


def _zap_findings() -> list[Finding]:
    return [
        make_finding(
            source="zap",
            host="10.0.0.10",
            title="Cross Site Scripting (Reflected)",
            severity=Severity.HIGH,
            port=443,
            plugin_id="40012",
        )
    ]


def _stub_scanners(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the registry lookup with canned Nmap / ZAP scanners."""
    canned = {"nmap": _nmap_findings(), "zap": _zap_findings()}

    def fake_get_scanner(name: str) -> type[BaseScanner]:
        findings = canned.get(name, [])

        class _Stub(BaseScanner):
            name = "stub"

            def scan(self) -> list[Finding]:
                return list(findings)

        return _Stub

    monkeypatch.setattr(orchestrator, "get_scanner", fake_get_scanner)


def _write_config(tmp_path: Path) -> Path:
    cfg = tmp_path / "targets.yaml"
    cfg.write_text(
        'scope:\n  hosts: ["10.0.0.0/24"]\n'
        'targets:\n  - host: "10.0.0.10"\n'
        "zap:\n  spider_max_duration_minutes: 0\n"
        "enrichment:\n  nvd_enabled: false\n  epss_enabled: false\n",
        encoding="utf-8",
    )
    return cfg


def test_scan_end_to_end_gates_on_new_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_scanners(monkeypatch)
    out = tmp_path / "results"
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
            str(out / "vulnpipe.sarif"),
            "--junit",
            str(out / "junit.xml"),
        ],
    )
    # New Critical + High findings against no baseline -> the gate fails.
    assert result.exit_code == 1

    report = json.loads((out / "latest.json").read_text(encoding="utf-8"))
    titles = [finding["title"] for finding in report["findings"]]
    assert "CVE-2021-44228" in titles
    assert "Cross Site Scripting (Reflected)" in titles
    # The web URL was discovered from the Nmap https service, then ZAP-scanned.
    assert report["findings"][0]["title"] == "CVE-2021-44228"  # prioritized: Critical first

    assert json.loads((out / "vulnpipe.sarif").read_text(encoding="utf-8"))["version"] == "2.1.0"
    junit = ET.fromstring((out / "junit.xml").read_text(encoding="utf-8"))
    assert int(junit.attrib["failures"]) >= 1


def test_baseline_then_scan_passes_the_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_scanners(monkeypatch)
    out = tmp_path / "results"
    config = str(_write_config(tmp_path))

    # First scan: write artifacts without failing the build.
    first = runner.invoke(app, ["scan", "-c", config, "--authorized", "-o", str(out), "--no-gate"])
    assert first.exit_code == 0

    # Accept the current findings as the baseline.
    baseline = tmp_path / "baseline.json"
    made = runner.invoke(app, ["baseline", "-i", str(out / "latest.json"), "-o", str(baseline)])
    assert made.exit_code == 0

    # Re-scan against the baseline: nothing is new, so the gate passes.
    second = runner.invoke(
        app, ["scan", "-c", config, "--authorized", "-o", str(out), "--baseline", str(baseline)]
    )
    assert second.exit_code == 0
