"""Unit tests for the Nmap scanner: command building and scope selection.

Parser-level tests (XML -> findings) and the subprocess-mocked scan() test live
alongside these; no test in this module runs the real nmap binary.
"""

import pytest

from vulnpipe.core.config import Config, NmapConfig, OutOfScopeError, Scope, Target
from vulnpipe.scanners.nmap_scanner import (
    SOURCE,
    build_nmap_command,
    select_network_targets,
)


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
