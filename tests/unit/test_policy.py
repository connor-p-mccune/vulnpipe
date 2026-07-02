"""Unit tests for the policy-as-code gate.

Cover YAML loading/validation, each rule in isolation and combined, the
threshold-to-policy bridge (equivalence with the plain severity gate), verdict
determinism, and the JSON payload shape.
"""

from pathlib import Path

import pytest

from vulnpipe.ci.baseline import Baseline, build_baseline
from vulnpipe.ci.differ import Diff, diff_findings
from vulnpipe.ci.gate import evaluate_gate
from vulnpipe.ci.policy import (
    GatePolicy,
    PolicyError,
    evaluate_policy,
    load_policy,
    policy_from_threshold,
    policy_result_to_payload,
)
from vulnpipe.core.models import Finding, Severity
from vulnpipe.processing.normalizer import make_finding


def _f(
    title: str,
    severity: Severity,
    *,
    kev: bool = False,
    cvss: float | None = None,
    epss: float | None = None,
) -> Finding:
    return make_finding(
        source="zap",
        host="10.0.0.10",
        title=title,
        severity=severity,
        plugin_id="p",
        kev=kev,
        cvss_score=cvss,
        epss_score=epss,
    )


def _diff(current: list[Finding], baselined: list[Finding] | None = None) -> Diff:
    baseline = build_baseline(baselined) if baselined else Baseline()
    return diff_findings(current, baseline)


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def test_load_policy_parses_all_rules(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(
        "max_new:\n  critical: 0\n  medium: 5\nmax_new_total: 20\n"
        "min_risk_score: 90\nblock_kev: true\n",
        encoding="utf-8",
    )
    policy = load_policy(path)
    assert policy.max_new == {Severity.CRITICAL: 0, Severity.MEDIUM: 5}
    assert policy.max_new_total == 20
    assert policy.min_risk_score == 90
    assert policy.block_kev is True


def test_load_policy_empty_file_is_permissive(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("", encoding="utf-8")
    policy = load_policy(path)
    assert policy == GatePolicy()
    assert policy.describe() == "no rules (permit all)"


def test_load_policy_missing_file_raises() -> None:
    with pytest.raises(PolicyError, match="not found"):
        load_policy("does/not/exist.yaml")


def test_load_policy_rejects_unknown_keys_and_bad_values(tmp_path: Path) -> None:
    bad_key = tmp_path / "bad-key.yaml"
    bad_key.write_text("maximum_new: {}\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="Invalid gate policy"):
        load_policy(bad_key)

    bad_value = tmp_path / "bad-value.yaml"
    bad_value.write_text("max_new:\n  high: -1\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="Invalid gate policy"):
        load_policy(bad_value)

    bad_root = tmp_path / "bad-root.yaml"
    bad_root.write_text("- not\n- a\n- mapping\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="must be a mapping"):
        load_policy(bad_root)

    unparseable = tmp_path / "unparseable.yaml"
    unparseable.write_text("max_new: [unclosed\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="Failed to parse"):
        load_policy(unparseable)


# --------------------------------------------------------------------------- #
# Rule evaluation
# --------------------------------------------------------------------------- #
def test_empty_policy_permits_everything() -> None:
    diff = _diff([_f("crit", Severity.CRITICAL, kev=True)])
    result = evaluate_policy(diff, GatePolicy())
    assert result.passed is True
    assert result.exit_code == 0
    assert result.violations == ()
    assert "gate passed" in result.summary


def test_severity_budget_flags_only_the_exceeded_band() -> None:
    policy = GatePolicy(max_new={Severity.HIGH: 1, Severity.MEDIUM: 5})
    diff = _diff([_f("h1", Severity.HIGH), _f("h2", Severity.HIGH), _f("m", Severity.MEDIUM)])
    result = evaluate_policy(diff, policy)
    assert result.passed is False
    assert [violation.rule for violation in result.violations] == ["max_new[high]"]
    assert {finding.title for finding in result.violations[0].findings} == {"h1", "h2"}


def test_budget_within_limit_passes() -> None:
    policy = GatePolicy(max_new={Severity.MEDIUM: 2})
    diff = _diff([_f("m1", Severity.MEDIUM), _f("m2", Severity.MEDIUM)])
    assert evaluate_policy(diff, policy).passed is True


def test_persisting_findings_never_violate() -> None:
    known = _f("known critical", Severity.CRITICAL, kev=True)
    policy = GatePolicy(max_new={Severity.CRITICAL: 0}, block_kev=True)
    diff = _diff([known], baselined=[known])
    assert evaluate_policy(diff, policy).passed is True


def test_max_new_total_counts_all_new_findings() -> None:
    policy = GatePolicy(max_new_total=1)
    diff = _diff([_f("a", Severity.LOW), _f("b", Severity.INFORMATIONAL)])
    result = evaluate_policy(diff, policy)
    assert [violation.rule for violation in result.violations] == ["max_new_total"]
    assert len(result.violations[0].findings) == 2


def test_min_risk_score_flags_risky_new_findings() -> None:
    policy = GatePolicy(min_risk_score=90)
    risky = _f("exploited", Severity.CRITICAL, kev=True, cvss=9.8)  # risk 98
    calm = _f("quiet", Severity.LOW)
    result = evaluate_policy(_diff([risky, calm]), policy)
    assert [violation.rule for violation in result.violations] == ["min_risk_score"]
    assert [finding.title for finding in result.violations[0].findings] == ["exploited"]


def test_block_kev_fails_on_any_new_kev_finding() -> None:
    policy = GatePolicy(block_kev=True)
    kev_medium = _f("exploited medium", Severity.MEDIUM, kev=True)
    result = evaluate_policy(_diff([kev_medium]), policy)
    assert result.passed is False
    assert [violation.rule for violation in result.violations] == ["block_kev"]


def test_violations_report_in_fixed_rule_order() -> None:
    policy = GatePolicy(
        max_new={Severity.MEDIUM: 0, Severity.CRITICAL: 0},
        max_new_total=0,
        min_risk_score=0,
        block_kev=True,
    )
    diff = _diff([_f("c", Severity.CRITICAL, kev=True), _f("m", Severity.MEDIUM)])
    result = evaluate_policy(diff, policy)
    assert [violation.rule for violation in result.violations] == [
        "max_new[critical]",  # budgets, worst band first
        "max_new[medium]",
        "max_new_total",
        "min_risk_score",
        "block_kev",
    ]
    # triggering de-duplicates findings across violations, first-seen order.
    assert [finding.title for finding in result.triggering] == ["c", "m"]


def test_describe_is_deterministic_and_complete() -> None:
    policy = GatePolicy(
        max_new={Severity.MEDIUM: 5, Severity.CRITICAL: 0},
        max_new_total=20,
        min_risk_score=90,
        block_kev=True,
    )
    assert policy.describe() == (
        "new critical <= 0; new medium <= 5; new total <= 20; " "risk < 90; no new known-exploited"
    )


# --------------------------------------------------------------------------- #
# Threshold bridge: policy_from_threshold matches the plain severity gate
# --------------------------------------------------------------------------- #
def test_policy_from_threshold_matches_evaluate_gate() -> None:
    findings = [
        _f("crit", Severity.CRITICAL),
        _f("high", Severity.HIGH),
        _f("med", Severity.MEDIUM, kev=True, cvss=6.5, epss=0.9),
        _f("low", Severity.LOW),
    ]
    diff = _diff(findings)
    for risk in (None, 50):
        gate = evaluate_gate(diff, threshold=Severity.HIGH, min_risk_score=risk)
        policy = policy_from_threshold(Severity.HIGH, min_risk_score=risk)
        verdict = evaluate_policy(diff, policy)
        assert verdict.passed == gate.passed
        assert {f.fingerprint for f in verdict.triggering} == {
            f.fingerprint for f in gate.triggering
        }


# --------------------------------------------------------------------------- #
# Payload
# --------------------------------------------------------------------------- #
def test_payload_shape_and_determinism() -> None:
    policy = GatePolicy(max_new={Severity.HIGH: 0}, block_kev=True)
    diff = _diff([_f("h", Severity.HIGH, kev=True)])
    result = evaluate_policy(diff, policy)
    payload = policy_result_to_payload(result)
    assert payload["passed"] is False
    assert payload["exit_code"] == 1
    violations = payload["violations"]
    assert isinstance(violations, list) and len(violations) == 2
    first = violations[0]["findings"][0]
    assert set(first) == {"fingerprint", "severity", "title", "host", "risk_score", "kev"}
    assert policy_result_to_payload(result) == payload  # deterministic
