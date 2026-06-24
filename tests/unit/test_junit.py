"""Unit tests for JUnit XML rendering of the gate outcome.

Asserts the document is valid, parseable XML with the right test/failure counts,
that only gate-triggering findings become failures, that content is escaped, and
that output is deterministic for fixed input.
"""

import xml.etree.ElementTree as ET

from vulnpipe.ci.baseline import build_baseline
from vulnpipe.ci.differ import diff_findings
from vulnpipe.ci.gate import evaluate_gate
from vulnpipe.ci.junit import build_junit_xml
from vulnpipe.core.models import Finding, Severity
from vulnpipe.processing.normalizer import make_finding


def _f(
    title: str,
    severity: Severity,
    *,
    host: str = "10.0.0.10",
    description: str | None = None,
) -> Finding:
    return make_finding(
        source="zap",
        host=host,
        title=title,
        severity=severity,
        port=443,
        plugin_id="p",
        description=description,
    )


def _render(current: list[Finding], baseline_findings: list[Finding]) -> str:
    diff = diff_findings(current, build_baseline(baseline_findings))
    return build_junit_xml(diff, evaluate_gate(diff))


def test_counts_and_failures() -> None:
    known = _f("known-high", Severity.HIGH)
    current = [
        _f("new-high", Severity.HIGH),  # new + High -> failure
        _f("new-low", Severity.LOW),  # new but below threshold -> pass
        known,  # persisting -> pass
    ]
    xml = _render(current, [known])
    root = ET.fromstring(xml)
    assert root.tag == "testsuites"
    assert root.attrib["tests"] == "3"
    assert root.attrib["failures"] == "1"
    suite = root.find("testsuite")
    assert suite is not None
    failures = suite.findall("./testcase/failure")
    assert len(failures) == 1
    assert "new-high" in failures[0].text  # body names the offending finding
    assert failures[0].attrib["type"] == "vulnpipe.severity-gate"


def test_persisting_findings_do_not_fail() -> None:
    known = _f("known", Severity.CRITICAL)
    xml = _render([known], [known])  # the Critical is baselined -> no failure
    root = ET.fromstring(xml)
    assert root.attrib["tests"] == "1"
    assert root.attrib["failures"] == "0"
    assert root.findall("./testsuite/testcase/failure") == []


def test_testcase_classnames_reflect_status() -> None:
    known = _f("known", Severity.MEDIUM)
    xml = _render([_f("fresh", Severity.MEDIUM), known], [known])
    classes = {tc.attrib["classname"] for tc in ET.fromstring(xml).iter("testcase")}
    assert classes == {"vulnpipe.new", "vulnpipe.persisting"}


def test_content_is_escaped_not_injected() -> None:
    payload = "Reflected XSS <script>alert(1)</script>"
    xml = _render([_f(payload, Severity.HIGH, description=payload)], [])
    # The raw markup never appears literally; ElementTree escapes it.
    assert "<script>" not in xml
    assert "&lt;script" in xml
    # Still valid XML and the failure body round-trips the unescaped text.
    failure = ET.fromstring(xml).find("./testsuite/testcase/failure")
    assert failure is not None and "<script>alert(1)</script>" in failure.text


def test_is_deterministic_and_has_declaration() -> None:
    current = [_f("a", Severity.HIGH), _f("b", Severity.LOW)]
    first = _render(current, [])
    assert first.startswith('<?xml version="1.0" encoding="utf-8"?>')
    assert _render(current, []) == first


def test_empty_scan_is_valid_empty_suite() -> None:
    xml = _render([], [])
    root = ET.fromstring(xml)
    assert root.attrib["tests"] == "0"
    assert root.attrib["failures"] == "0"
    assert list(root.find("testsuite")) == []
