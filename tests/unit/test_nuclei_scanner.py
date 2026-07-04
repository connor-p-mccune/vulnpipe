"""Unit tests for the Nuclei scanner: command building, parsing, scope, and scan().

Parser-level tests (JSONL -> findings) and the subprocess-mocked scan() test live
here; no test in this module runs the real nuclei binary.
"""

import subprocess
from pathlib import Path
from typing import Any

import pytest

from vulnpipe.core.config import Config, NucleiConfig, OutOfScopeError, Scope, Target
from vulnpipe.core.models import Confidence, Severity
from vulnpipe.scanners import nuclei_scanner
from vulnpipe.scanners.nuclei_scanner import (
    SOURCE,
    NucleiScanner,
    _host_port,
    build_nuclei_command,
    parse_nuclei_jsonl,
    result_to_finding,
    select_nuclei_targets,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _config(
    *,
    nuclei: NucleiConfig | None = None,
    targets: list[Target] | None = None,
    scope: Scope | None = None,
) -> Config:
    return Config(
        scope=scope or Scope(hosts=["10.0.0.0/24"], urls=["https://app.lab.example.com"]),
        targets=targets or [Target(urls=["https://app.lab.example.com"])],
        nuclei=nuclei or NucleiConfig(enabled=True),
    )


# --------------------------------------------------------------------------- #
# Command construction
# --------------------------------------------------------------------------- #
def test_build_command_emits_jsonl_and_targets() -> None:
    command = build_nuclei_command(_config(), ["https://app.lab.example.com"])
    assert command[0] == "nuclei"
    assert "-jsonl" in command
    assert "-disable-update-check" in command  # never phones home mid-scan
    assert command[-2:] == ["-u", "https://app.lab.example.com"]  # targets last


def test_build_command_applies_severities_templates_and_rate_limit() -> None:
    cfg = _config(
        nuclei=NucleiConfig(
            enabled=True,
            severities=["High", "critical"],
            templates=["http/cves", "http/exposures"],
            rate_limit=50,
        )
    )
    command = build_nuclei_command(cfg, ["https://app.lab.example.com"])
    assert command[command.index("-severity") + 1] == "high,critical"  # normalized, joined
    assert command.count("-t") == 2
    assert command[command.index("-rate-limit") + 1] == "50"


# --------------------------------------------------------------------------- #
# Target selection & scope
# --------------------------------------------------------------------------- #
def test_select_targets_dedupes_in_order() -> None:
    cfg = _config(
        targets=[
            Target(urls=["https://app.lab.example.com"]),
            Target(urls=["https://app.lab.example.com"]),
        ]
    )
    assert select_nuclei_targets(cfg) == ["https://app.lab.example.com"]


def test_select_targets_rejects_out_of_scope() -> None:
    cfg = _config(
        scope=Scope(urls=["https://app.lab.example.com"]),
        targets=[Target(urls=["https://app.lab.example.com"])],
    )
    # A URL not covered by scope must raise before any scan.
    bad = cfg.model_copy(update={"targets": [Target(urls=["https://evil.example.net"])]})
    with pytest.raises(OutOfScopeError):
        select_nuclei_targets(bad)


# --------------------------------------------------------------------------- #
# Host/port parsing
# --------------------------------------------------------------------------- #
def test_host_port_from_url_and_hostport() -> None:
    assert _host_port("https://app.lab.example.com") == ("app.lab.example.com", 443)
    assert _host_port("http://10.0.0.5") == ("10.0.0.5", 80)
    assert _host_port("app.lab.example.com:8443") == ("app.lab.example.com", 8443)
    assert _host_port("10.0.0.5") == ("10.0.0.5", None)
    assert _host_port("") == (None, None)


# --------------------------------------------------------------------------- #
# Parsing JSONL -> findings
# --------------------------------------------------------------------------- #
def test_parse_maps_fields_and_orders_deterministically() -> None:
    findings = parse_nuclei_jsonl(_load("nuclei_results.jsonl"))
    # Five results in the fixture; every one is parseable (scope not applied here).
    assert len(findings) == 5
    assert all(finding.source == SOURCE for finding in findings)
    # Deterministic host-first ordering: 10.0.0.5 sorts before the app host.
    assert findings[0].host == "10.0.0.5"


def test_parse_maps_severity_cve_cwe_and_cvss() -> None:
    by_title = {f.title: f for f in parse_nuclei_jsonl(_load("nuclei_results.jsonl"))}
    log4j = by_title["Apache Log4j2 Remote Code Injection"]
    assert log4j.severity is Severity.CRITICAL
    assert log4j.plugin_id == "CVE-2021-44228"
    assert log4j.cve_ids == ("CVE-2021-44228",)
    assert log4j.cwe_ids == ("CWE-502", "CWE-917")  # normalized from "cwe-502" etc.
    assert log4j.cvss_score == 10.0
    assert log4j.solution == "Upgrade to Log4j 2.17.0 or later."
    assert log4j.confidence is Confidence.MEDIUM


def test_parse_scope_filter_drops_out_of_scope_result() -> None:
    scope = Scope(hosts=["10.0.0.0/24"], urls=["https://app.lab.example.com"])
    findings = parse_nuclei_jsonl(_load("nuclei_results.jsonl"), scope=scope)
    # The external.attacker.test result is dropped; the four in-scope ones remain.
    assert len(findings) == 4
    assert all("attacker" not in finding.host for finding in findings)


def test_result_without_host_is_skipped() -> None:
    assert result_to_finding({"info": {"name": "X", "severity": "low"}}) is None


def test_result_without_title_is_skipped() -> None:
    assert result_to_finding({"host": "https://app.lab.example.com"}) is None


def test_unknown_severity_degrades_to_informational() -> None:
    finding = result_to_finding(
        {"host": "https://app.lab.example.com", "info": {"name": "X", "severity": "unknown"}}
    )
    assert finding is not None
    assert finding.severity is Severity.INFORMATIONAL


def test_invalid_json_line_is_skipped() -> None:
    good = '{"host":"https://app.lab.example.com","info":{"name":"Ok","severity":"low"}}'
    findings = parse_nuclei_jsonl(good + "\nnot json\n")
    assert len(findings) == 1
    assert findings[0].title == "Ok"


# --------------------------------------------------------------------------- #
# scan() with a mocked subprocess
# --------------------------------------------------------------------------- #
class _Completed:
    def __init__(self, stdout: str, returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


def test_scan_runs_and_parses(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_run(command: list[str], **kwargs: Any) -> _Completed:
        captured["command"] = command
        return _Completed(_load("nuclei_results.jsonl"))

    monkeypatch.setattr(nuclei_scanner.subprocess, "run", fake_run)
    findings = NucleiScanner(_config()).scan()
    # Scope is applied in scan(), so the out-of-scope fixture line is dropped.
    assert len(findings) == 4
    assert captured["command"][0] == "nuclei"


def test_scan_disabled_returns_empty() -> None:
    assert NucleiScanner(_config(nuclei=NucleiConfig(enabled=False))).scan() == []


def test_scan_no_targets_returns_empty() -> None:
    cfg = Config(
        scope=Scope(hosts=["10.0.0.0/24"]),
        targets=[Target(host="10.0.0.5")],  # network-only, no URLs
        nuclei=NucleiConfig(enabled=True),
    )
    assert NucleiScanner(cfg).scan() == []


def test_scan_binary_missing_degrades_to_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(command: list[str], **kwargs: Any) -> _Completed:
        raise FileNotFoundError(command[0])

    monkeypatch.setattr(nuclei_scanner.subprocess, "run", boom)
    assert NucleiScanner(_config()).scan() == []


def test_scan_timeout_keeps_partial_output(monkeypatch: pytest.MonkeyPatch) -> None:
    partial = _load("nuclei_results.jsonl")

    def slow(command: list[str], **kwargs: Any) -> _Completed:
        raise subprocess.TimeoutExpired(cmd=command, timeout=1, output=partial)

    monkeypatch.setattr(nuclei_scanner.subprocess, "run", slow)
    findings = NucleiScanner(_config()).scan()
    assert len(findings) == 4  # best-effort partial output still parsed (scope applied)


def test_scanner_registered() -> None:
    from vulnpipe.scanners.registry import get_scanner

    assert get_scanner(SOURCE) is NucleiScanner
