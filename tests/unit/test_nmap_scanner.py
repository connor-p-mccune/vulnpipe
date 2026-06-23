"""Unit tests for the Nmap scanner: command building and scope selection.

Parser-level tests (XML -> findings) and the subprocess-mocked scan() test live
alongside these; no test in this module runs the real nmap binary.
"""

import subprocess
from pathlib import Path

import pytest

from vulnpipe.core.config import Config, NmapConfig, OutOfScopeError, Scope, Target
from vulnpipe.core.models import Confidence, Finding, Severity
from vulnpipe.scanners import nmap_scanner
from vulnpipe.scanners.nmap_scanner import (
    SOURCE,
    NmapScanner,
    _confidence_from_conf,
    _cve_confidence,
    _CveHit,
    _decode,
    _harvest_cves,
    _harvest_from_text,
    _parse_bool,
    _service_summary,
    _truncate,
    build_nmap_command,
    parse_nmap_xml,
    select_network_targets,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _config(
    *,
    nmap: NmapConfig | None = None,
    targets: list[Target] | None = None,
    scope: Scope | None = None,
) -> Config:
    return Config(
        scope=scope or Scope(hosts=["10.0.0.0/24"]),
        targets=targets or [Target(host="10.0.0.0/24")],
        nmap=nmap or NmapConfig(),
    )


def test_build_command_includes_xml_stdout_and_service_detection() -> None:
    command = build_nmap_command(_config(), ["10.0.0.0/24"])
    assert command[0] == "nmap"
    assert command[1:3] == ["-oX", "-"]  # XML to stdout
    assert "-sV" in command
    assert "-T4" in command


def test_build_command_uses_top_ports_and_scripts() -> None:
    cfg = _config(nmap=NmapConfig(top_ports=1000, scripts=["vulners"]))
    command = build_nmap_command(cfg, ["10.0.0.5"])
    assert command[command.index("--top-ports") + 1] == "1000"
    assert command[command.index("--script") + 1] == "vulners"
    assert command[-1] == "10.0.0.5"  # targets come last


def test_build_command_explicit_ports_take_precedence_over_top_ports() -> None:
    cfg = _config(nmap=NmapConfig(ports="22,80,443", top_ports=1000))
    command = build_nmap_command(cfg, ["10.0.0.5"])
    assert "-p" in command and command[command.index("-p") + 1] == "22,80,443"
    assert "--top-ports" not in command


def test_build_command_honours_binary_timing_and_extra_args() -> None:
    cfg = _config(nmap=NmapConfig(binary="/usr/bin/nmap", timing_template=3, extra_args=["-Pn"]))
    command = build_nmap_command(cfg, ["10.0.0.5"])
    assert command[0] == "/usr/bin/nmap"
    assert "-T3" in command
    assert "-Pn" in command


def test_build_command_omits_script_flag_when_no_scripts() -> None:
    command = build_nmap_command(_config(nmap=NmapConfig(scripts=[])), ["10.0.0.5"])
    assert "--script" not in command


def test_build_command_appends_targets_as_separate_args() -> None:
    targets = ["10.0.0.0/24", "host.lab.example.com"]
    command = build_nmap_command(_config(), targets)
    assert command[-2:] == targets  # never joined / shell-interpolated


def test_select_network_targets_dedupes_and_skips_url_only() -> None:
    cfg = _config(
        scope=Scope(hosts=["10.0.0.0/24"], urls=["https://app.lab.example.com"]),
        targets=[
            Target(name="net", host="10.0.0.5"),
            Target(name="dup", host="10.0.0.5"),
            Target(name="web", urls=["https://app.lab.example.com"]),
        ],
    )
    assert select_network_targets(cfg) == ["10.0.0.5"]


def test_select_network_targets_rejects_out_of_scope_host() -> None:
    cfg = _config(
        scope=Scope(hosts=["10.0.0.0/24"]),
        targets=[Target(host="10.0.0.5"), Target(host="192.168.1.1")],
    )
    with pytest.raises(OutOfScopeError):
        select_network_targets(cfg)


def test_source_constant() -> None:
    assert SOURCE == "nmap"


# --------------------------------------------------------------------------- #
# Parsing the captured fixtures into findings
# --------------------------------------------------------------------------- #
def _by_cve(findings: list[Finding]) -> dict[str, Finding]:
    return {f.cve_ids[0]: f for f in findings if f.cve_ids}


def test_parse_vulners_fixture_shape_and_ordering() -> None:
    findings = parse_nmap_xml(_load("nmap_vulners.xml"), scope_hosts=["10.0.0.0/24"])
    assert len(findings) == 9
    # Deterministic ordering: by host, then port (open-service finding before CVEs).
    assert [(f.host, f.port) for f in findings] == [
        ("10.0.0.5", 22),
        ("10.0.0.5", 22),
        ("10.0.0.5", 22),
        ("10.0.0.5", 80),
        ("10.0.0.5", 80),
        ("10.0.0.5", 80),
        ("10.0.0.6", 443),
        ("10.0.0.6", 443),
        ("10.0.0.6", 3306),
    ]
    assert {f.source for f in findings} == {"nmap"}
    # Fingerprints are unique and stable across re-parses.
    assert len({f.fingerprint for f in findings}) == len(findings)
    again = parse_nmap_xml(_load("nmap_vulners.xml"), scope_hosts=["10.0.0.0/24"])
    assert [f.fingerprint for f in findings] == [f.fingerprint for f in again]


def test_parse_vulners_cve_findings() -> None:
    cves = _by_cve(parse_nmap_xml(_load("nmap_vulners.xml"), scope_hosts=["10.0.0.0/24"]))
    assert set(cves) == {
        "CVE-2016-10009",
        "CVE-2018-15473",
        "CVE-2021-41773",
        "CVE-2021-42013",
        "CVE-2021-23017",
    }
    # Severity is derived from the scanner-supplied CVSS score.
    assert cves["CVE-2021-42013"].severity is Severity.CRITICAL
    assert cves["CVE-2021-42013"].cvss_score == 9.8
    assert cves["CVE-2016-10009"].severity is Severity.HIGH
    assert cves["CVE-2018-15473"].severity is Severity.MEDIUM
    assert cves["CVE-2021-23017"].cvss_score == 7.7

    critical = cves["CVE-2021-42013"]
    assert critical.plugin_id == "vulners"
    assert critical.cve_ids == ("CVE-2021-42013",)
    assert critical.port == 80 and critical.protocol == "tcp"
    assert critical.confidence is Confidence.MEDIUM
    assert critical.metadata["product"] == "Apache httpd"
    assert critical.metadata["nmap_script"] == "vulners"
    assert critical.metadata["is_exploit"] is True


def test_parse_vulners_open_service_findings() -> None:
    findings = parse_nmap_xml(_load("nmap_vulners.xml"), scope_hosts=["10.0.0.0/24"])
    open_ports = [f for f in findings if f.plugin_id is None]
    assert {f.port for f in open_ports} == {22, 80, 443, 3306}
    for finding in open_ports:
        assert finding.severity is Severity.INFORMATIONAL
        assert finding.title.startswith("Open port")
        assert finding.cve_ids == ()
    # A service with no vuln scripts still yields its inventory finding.
    mysql = next(f for f in open_ports if f.port == 3306)
    assert mysql.metadata["product"] == "MySQL"
    assert mysql.metadata["os"] == "Linux 5.0 - 5.4"
    assert mysql.confidence is Confidence.CONFIRMED


def test_parse_basic_fixture_services_only() -> None:
    findings = parse_nmap_xml(_load("sample_nmap.xml"), scope_hosts=["10.0.0.0/24"])
    assert len(findings) == 2
    assert all(f.severity is Severity.INFORMATIONAL for f in findings)
    assert all(f.cve_ids == () for f in findings)
    ssh = next(f for f in findings if f.port == 22)
    assert ssh.metadata["product"] == "OpenSSH"
    assert ssh.metadata["os"] == "Linux 5.0 - 5.4"
    assert ssh.metadata["hostname"] == "host.lab.example.com"


def test_parse_drops_out_of_scope_hosts() -> None:
    assert parse_nmap_xml(_load("nmap_vulners.xml"), scope_hosts=["192.168.0.0/16"]) == []


def test_parse_without_scope_includes_all_hosts() -> None:
    assert len(parse_nmap_xml(_load("nmap_vulners.xml"))) == 9


@pytest.mark.parametrize("xml", ["", "   ", "<foo/>", "<nmaprun><host", "not xml at all"])
def test_parse_bad_xml_returns_empty(xml: str) -> None:
    assert parse_nmap_xml(xml) == []


# --------------------------------------------------------------------------- #
# CVE harvesting from NSE element structures
# --------------------------------------------------------------------------- #
def test_harvest_cves_vulners_list_shape() -> None:
    elements = {
        "cpe:/a:openbsd:openssh:7.4": {
            None: [
                {"type": "cve", "id": "CVE-2016-10009", "cvss": "7.5", "is_exploit": "true"},
                {"type": "cve", "id": "CVE-2018-15473", "cvss": "5.3", "is_exploit": "false"},
            ]
        }
    }
    hits = _harvest_cves(elements)
    assert set(hits) == {"CVE-2016-10009", "CVE-2018-15473"}
    assert hits["CVE-2016-10009"].cvss == 7.5
    assert hits["CVE-2016-10009"].is_exploit is True
    assert hits["CVE-2018-15473"].cvss == 5.3


def test_harvest_cves_single_dict_shape() -> None:
    elements = {"cpe:/a:nginx:nginx:1.18.0": {None: {"id": "CVE-2021-23017", "cvss": "7.7"}}}
    hits = _harvest_cves(elements)
    assert set(hits) == {"CVE-2021-23017"}
    assert hits["CVE-2021-23017"].cvss == 7.7


def test_harvest_cves_vuln_category_keyed_shape() -> None:
    elements = {"CVE-2014-0160": {"title": "Heartbleed", "state": "VULNERABLE"}}
    hits = _harvest_cves(elements)
    assert set(hits) == {"CVE-2014-0160"}
    assert hits["CVE-2014-0160"].state == "VULNERABLE"
    assert hits["CVE-2014-0160"].title == "Heartbleed"
    assert hits["CVE-2014-0160"].cvss is None


def test_harvest_cves_ignores_non_cve_ids() -> None:
    assert _harvest_cves({"id": "not-a-cve", "cvss": "5.0"}) == {}


def test_harvest_from_text_backfills_and_dedupes() -> None:
    hits = _harvest_cves(None)
    _harvest_from_text("see CVE-2019-1234, CVE-2019-1234 and some junk", hits)
    assert set(hits) == {"CVE-2019-1234"}


def test_harvest_from_text_does_not_override_structured_score() -> None:
    hits = _harvest_cves({"id": "CVE-2016-10009", "cvss": "7.5"})
    _harvest_from_text("CVE-2016-10009 mentioned again", hits)
    assert hits["CVE-2016-10009"].cvss == 7.5  # structured score preserved


# --------------------------------------------------------------------------- #
# NmapScanner.scan() with the subprocess mocked (no real nmap)
# --------------------------------------------------------------------------- #
class _FakeCompleted:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _patch_run(
    monkeypatch: pytest.MonkeyPatch,
    *,
    result: _FakeCompleted | None = None,
    exc: BaseException | None = None,
) -> dict[str, list[str]]:
    calls: dict[str, list[str]] = {}

    def fake_run(command: list[str], **kwargs: object) -> _FakeCompleted:
        calls["command"] = list(command)
        if exc is not None:
            raise exc
        assert result is not None
        return result

    monkeypatch.setattr(nmap_scanner.subprocess, "run", fake_run)
    return calls


def test_scan_parses_mocked_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_run(monkeypatch, result=_FakeCompleted(0, _load("nmap_vulners.xml")))
    findings = NmapScanner(_config()).scan()
    assert len(findings) == 9
    assert calls["command"][0] == "nmap"
    assert "-oX" in calls["command"]


def test_scan_missing_binary_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, exc=FileNotFoundError())
    assert NmapScanner(_config()).scan() == []


def test_scan_timeout_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, exc=subprocess.TimeoutExpired(cmd=["nmap"], timeout=1))
    assert NmapScanner(_config()).scan() == []


def test_scan_parses_partial_output_on_nonzero_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, result=_FakeCompleted(1, _load("nmap_vulners.xml"), "a warning"))
    assert len(NmapScanner(_config()).scan()) == 9


def test_scan_empty_output_on_nonzero_exit_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_run(monkeypatch, result=_FakeCompleted(2, "", "boom"))
    assert NmapScanner(_config()).scan() == []


def test_scan_disabled_skips_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object) -> object:
        raise AssertionError("subprocess.run must not run when nmap is disabled")

    monkeypatch.setattr(nmap_scanner.subprocess, "run", boom)
    assert NmapScanner(_config(nmap=NmapConfig(enabled=False))).scan() == []


def test_scan_no_in_scope_targets_skips_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object) -> object:
        raise AssertionError("subprocess.run must not run with no network targets")

    monkeypatch.setattr(nmap_scanner.subprocess, "run", boom)
    cfg = _config(
        scope=Scope(urls=["https://app.lab.example.com"]),
        targets=[Target(urls=["https://app.lab.example.com"])],
    )
    assert NmapScanner(cfg).scan() == []


# --------------------------------------------------------------------------- #
# Value helpers and the host-level script path
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (True, True),
        (False, False),
        ("true", True),
        ("YES", True),
        ("1", True),
        ("false", False),
        ("no", False),
        ("0", False),
        ("maybe", None),
        (None, None),
    ],
)
def test_parse_bool(value: object, expected: bool | None) -> None:
    assert _parse_bool(value) is expected


@pytest.mark.parametrize(
    ("conf", "expected"),
    [
        (10, Confidence.CONFIRMED),
        (9, Confidence.CONFIRMED),
        (8, Confidence.HIGH),
        (7, Confidence.HIGH),
        (6, Confidence.MEDIUM),
        (4, Confidence.MEDIUM),
        (3, Confidence.LOW),
        (1, Confidence.LOW),
        (0, None),
        (None, None),
        ("not-a-number", None),
    ],
)
def test_confidence_from_conf(conf: object, expected: Confidence | None) -> None:
    assert _confidence_from_conf(conf) is expected


@pytest.mark.parametrize(
    ("name", "product", "version", "expected"),
    [
        ("ssh", "OpenSSH", "7.4", "ssh (OpenSSH 7.4)"),
        ("ssh", None, None, "ssh"),
        (None, "OpenSSH", "7.4", "OpenSSH 7.4"),
        ("https", "nginx", None, "https (nginx)"),
        (None, None, None, None),
    ],
)
def test_service_summary(
    name: str | None, product: str | None, version: str | None, expected: str | None
) -> None:
    assert _service_summary(name, product, version) == expected


def test_truncate() -> None:
    assert _truncate(None) is None
    assert _truncate("   ") is None
    assert _truncate("short") == "short"
    truncated = _truncate("x" * 600, limit=500)
    assert truncated is not None
    assert truncated.endswith("...")
    assert len(truncated) == 503


def test_decode() -> None:
    assert _decode(b"hello") == "hello"
    assert _decode("hi") == "hi"
    assert _decode(b"") is None
    assert _decode(None) is None


def test_cve_confidence_levels() -> None:
    assert _cve_confidence(_CveHit(cve="CVE-1", state="VULNERABLE")) is Confidence.HIGH
    assert _cve_confidence(_CveHit(cve="CVE-1", cvss=7.5)) is Confidence.MEDIUM
    assert _cve_confidence(_CveHit(cve="CVE-1")) is Confidence.LOW


_HOST_SCRIPT_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap" start="0" version="7.94" xmloutputversion="1.05">
  <host starttime="0" endtime="0">
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.7" addrtype="ipv4"/>
    <hostnames></hostnames>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open" reason="syn-ack"/>
        <service name="microsoft-ds" method="probed" conf="10"/>
      </port>
    </ports>
    <hostscript>
      <script id="smb-vuln-ms17-010" output="VULNERABLE: Remote Code Execution (MS17-010)">
        <table key="CVE-2017-0143">
          <elem key="title">Remote Code Execution vulnerability in SMBv1</elem>
          <elem key="state">VULNERABLE</elem>
        </table>
      </script>
    </hostscript>
  </host>
</nmaprun>"""


def test_parse_host_level_script_findings() -> None:
    findings = parse_nmap_xml(_HOST_SCRIPT_XML, scope_hosts=["10.0.0.0/24"])
    # One open-service finding (445) plus one host-level CVE finding (no port).
    assert {f.port for f in findings} == {445, None}
    cve = next(f for f in findings if f.cve_ids)
    assert cve.cve_ids == ("CVE-2017-0143",)
    assert cve.port is None
    assert cve.plugin_id == "smb-vuln-ms17-010"
    assert cve.confidence is Confidence.HIGH  # state VULNERABLE -> actively confirmed
    assert cve.severity is Severity.INFORMATIONAL  # no CVSS -> unknown, not guessed
    assert cve.description == "Remote Code Execution vulnerability in SMBv1"
