"""Unit tests for the CI failure gate.

Exercises the gate end-to-end against diffs built from synthetic baseline-vs-current
pairs, including the headline path: a newly introduced High finding must fail the
gate and yield a non-zero exit code, while a High that is already baselined must not.
"""

import pytest

from vulnpipe.ci.baseline import build_baseline
from vulnpipe.ci.differ import diff_findings
from vulnpipe.ci.gate import (
    DEFAULT_GATE_SEVERITY,
    GateResult,
    evaluate_gate,
    meets_threshold,
)
from vulnpipe.core.models import Finding, Severity
from vulnpipe.processing.normalizer import make_finding


def _f(
    title: str,
    severity: Severity,
    *,
    host: str = "10.0.0.10",
    cvss: float | None = None,
    kev: bool = False,
) -> Finding:
    return make_finding(
        source="nmap",
        host=host,
        title=title,
        severity=severity,
        plugin_id="p",
        cvss_score=cvss,
        kev=kev,
    )


def test_default_threshold_is_high() -> None:
    assert DEFAULT_GATE_SEVERITY is Severity.HIGH


def test_new_high_finding_fails_the_gate() -> None:
    # No baseline: the High finding is new, so the gate must fail with exit code 1.
    diff = diff_findings([_f("RCE", Severity.HIGH)], build_baseline([]))
    result = evaluate_gate(diff)
    assert result.passed is False
    assert result.exit_code == 1
    assert [f.title for f in result.triggering] == ["RCE"]
    assert "gate failed" in result.summary


def test_new_critical_finding_fails_the_gate() -> None:
    diff = diff_findings([_f("wormable", Severity.CRITICAL)], build_baseline([]))
    assert evaluate_gate(diff).exit_code == 1


def test_new_medium_finding_passes_the_gate() -> None:
    diff = diff_findings([_f("info-leak", Severity.MEDIUM)], build_baseline([]))
    result = evaluate_gate(diff)
    assert result.passed is True
    assert result.exit_code == 0
    assert result.triggering == ()
    assert "gate passed" in result.summary


def test_baselined_high_finding_does_not_trip_the_gate() -> None:
    # A High finding already present in the baseline is accepted, not "new".
    high = _f("known-high", Severity.HIGH)
    diff = diff_findings([high], build_baseline([high]))
    result = evaluate_gate(diff)
    assert result.passed is True
    assert result.exit_code == 0


def test_only_new_findings_above_threshold_trigger() -> None:
    known_high = _f("known-high", Severity.HIGH)
    baseline = build_baseline([known_high])
    current = [
        known_high,  # persisting High -> exempt
        _f("new-high", Severity.HIGH),  # new High -> triggers
        _f("new-low", Severity.LOW),  # new but below threshold -> ignored
    ]
    result = evaluate_gate(diff_findings(current, baseline))
    assert result.exit_code == 1
    assert [f.title for f in result.triggering] == ["new-high"]


def test_threshold_is_configurable() -> None:
    diff = diff_findings([_f("high", Severity.HIGH)], build_baseline([]))
    # Raising the bar to Critical lets a new High pass.
    assert evaluate_gate(diff, threshold=Severity.CRITICAL).exit_code == 0
    # Lowering it to Medium fails on the same High.
    assert evaluate_gate(diff, threshold=Severity.MEDIUM).exit_code == 1


def test_risk_score_threshold_fails_below_severity_bar() -> None:
    # A new Medium that is below the severity bar but has a high risk score
    # (KEV-driven) trips the gate once a risk threshold is set.
    medium_kev = _f("exploited-medium", Severity.MEDIUM, cvss=6.9, kev=True)
    assert medium_kev.risk_score >= 60
    diff = diff_findings([medium_kev], build_baseline([]))
    assert evaluate_gate(diff).exit_code == 0  # severity gate alone passes
    result = evaluate_gate(diff, min_risk_score=60)
    assert result.exit_code == 1
    assert [f.title for f in result.triggering] == ["exploited-medium"]
    assert "risk >= 60" in result.summary


def test_risk_score_threshold_not_met_passes() -> None:
    low = _f("minor", Severity.LOW, cvss=2.0)
    diff = diff_findings([low], build_baseline([]))
    result = evaluate_gate(diff, min_risk_score=80)
    assert result.passed is True
    assert "risk >= 80" in result.summary  # criterion is reported even when it passes


def test_severity_and_risk_criteria_union() -> None:
    current = [
        _f("new-high", Severity.HIGH),  # trips on severity
        _f("exploited-medium", Severity.MEDIUM, cvss=6.9, kev=True),  # trips on risk
        _f("quiet-low", Severity.LOW, cvss=1.0),  # trips on neither
    ]
    result = evaluate_gate(diff_findings(current, build_baseline([])), min_risk_score=60)
    assert result.exit_code == 1
    assert [f.title for f in result.triggering] == ["new-high", "exploited-medium"]


def test_triggering_preserves_diff_order() -> None:
    current = [
        _f("a", Severity.CRITICAL),
        _f("b", Severity.MEDIUM),
        _f("c", Severity.HIGH),
    ]
    result = evaluate_gate(diff_findings(current, build_baseline([])))
    assert [f.title for f in result.triggering] == ["a", "c"]


def test_clean_diff_passes() -> None:
    result = evaluate_gate(diff_findings([], build_baseline([])))
    assert isinstance(result, GateResult)
    assert result.passed is True


@pytest.mark.parametrize(
    ("severity", "threshold", "expected"),
    [
        (Severity.CRITICAL, Severity.HIGH, True),
        (Severity.HIGH, Severity.HIGH, True),
        (Severity.MEDIUM, Severity.HIGH, False),
        (Severity.LOW, Severity.HIGH, False),
        (Severity.INFORMATIONAL, Severity.INFORMATIONAL, True),
    ],
)
def test_meets_threshold(severity: Severity, threshold: Severity, expected: bool) -> None:
    assert meets_threshold(_f("x", severity), threshold) is expected
