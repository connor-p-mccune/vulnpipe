"""Render the gate outcome as a JUnit XML report.

CI systems and dashboards consume JUnit XML natively, so the security gate is
expressed in that vocabulary: every finding in the current scan (new + persisting)
becomes a ``<testcase>``, and each finding the gate flagged -- a *new* finding at
or above the threshold -- becomes a ``<failure>`` so the build turns red on exactly
the regressions the gate caught. Persisting (baselined) findings are emitted as
passing test cases, giving a full picture of the current state without failing the
build. Resolved findings are not part of the current scan, so they are not emitted.

The XML is generated through :mod:`xml.etree.ElementTree`, which escapes all text
and attribute content -- so scanner evidence such as a reflected ``<script>``
payload appears as inert text. Output is deterministic for fixed input: test cases
follow the diff's (prioritized) order and no timestamp or duration is embedded.
"""

import xml.etree.ElementTree as ET
from typing import Protocol

from vulnpipe.ci.differ import Diff
from vulnpipe.core.models import Finding

_SUITE_NAME = "vulnpipe.security-gate"
_FAILURE_TYPE = "vulnpipe.severity-gate"
_XML_DECLARATION = '<?xml version="1.0" encoding="utf-8"?>\n'


class GateVerdict(Protocol):
    """The common surface of a gate outcome (severity gate or policy).

    Satisfied structurally by both :class:`~vulnpipe.ci.gate.GateResult` (the plain
    severity gate) and :class:`~vulnpipe.ci.policy.PolicyResult` (policy-as-code),
    so JUnit rendering and the CLI serve either verdict through one path.
    """

    @property
    def passed(self) -> bool: ...

    @property
    def exit_code(self) -> int: ...

    @property
    def summary(self) -> str: ...

    @property
    def triggering(self) -> tuple[Finding, ...]: ...

    @property
    def criteria(self) -> str: ...


def _location(finding: Finding) -> str:
    """A compact ``host`` / ``host:port`` / URL location label for a finding."""
    url = finding.metadata.get("url")
    if isinstance(url, str) and url:
        return url
    return finding.host if finding.port is None else f"{finding.host}:{finding.port}"


def _case_name(finding: Finding) -> str:
    """Human-readable test-case name: ``[severity] title @ location``."""
    return f"[{finding.severity.value}] {finding.title} @ {_location(finding)}"


def _failure_body(finding: Finding, gate: GateVerdict) -> str:
    """The detail text for a failing test case (kept deterministic and concise)."""
    lines = [
        f"New finding fails the security gate ({gate.criteria}).",
        f"finding: {finding.title}",
        f"severity: {finding.severity.value}",
        f"location: {_location(finding)}",
        f"fingerprint: {finding.fingerprint}",
    ]
    if finding.description:
        lines.append(f"description: {finding.description}")
    return "\n".join(lines)


def _append_case(
    suite: ET.Element, finding: Finding, status: str, gate: GateVerdict, *, failed: bool
) -> None:
    """Append a ``<testcase>`` (with a ``<failure>`` child when ``failed``)."""
    case = ET.SubElement(
        suite,
        "testcase",
        {"classname": f"vulnpipe.{status}", "name": _case_name(finding)},
    )
    if failed:
        failure = ET.SubElement(
            case,
            "failure",
            {
                "message": f"New {finding.severity.value} finding fails the security gate",
                "type": _FAILURE_TYPE,
            },
        )
        failure.text = _failure_body(finding, gate)


def build_junit_xml(diff: Diff, gate: GateVerdict) -> str:
    """Render ``diff`` and the ``gate`` outcome as a JUnit XML document string.

    ``gate`` may be the plain severity :class:`~vulnpipe.ci.gate.GateResult` or a
    :class:`~vulnpipe.ci.policy.PolicyResult`. Test cases are the current findings
    (``new`` first, then ``persisting``); failures are the gate's triggering
    findings. Deterministic for fixed input.
    """
    triggering = {finding.fingerprint for finding in gate.triggering}
    total = len(diff.new) + len(diff.persisting)

    root = ET.Element(
        "testsuites",
        {
            "name": "vulnpipe",
            "tests": str(total),
            "failures": str(len(gate.triggering)),
            "errors": "0",
            "skipped": "0",
        },
    )
    suite = ET.SubElement(
        root,
        "testsuite",
        {
            "name": _SUITE_NAME,
            "tests": str(total),
            "failures": str(len(gate.triggering)),
            "errors": "0",
            "skipped": "0",
        },
    )
    for finding in diff.new:
        _append_case(suite, finding, "new", gate, failed=finding.fingerprint in triggering)
    for finding in diff.persisting:
        _append_case(suite, finding, "persisting", gate, failed=False)

    ET.indent(root, space="  ")
    return _XML_DECLARATION + ET.tostring(root, encoding="unicode") + "\n"


__all__ = ["GateVerdict", "build_junit_xml"]
