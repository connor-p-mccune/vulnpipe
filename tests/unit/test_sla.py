"""Unit tests for remediation-SLA evaluation over finding age.

Cover the per-severity deadline model, the age math against an injected evaluation
date, tracked/untracked accounting, deterministic worst-first ordering, the text and
JSON renders, and policy loading.
"""

from datetime import date
from pathlib import Path

import pytest

from vulnpipe.ci.baseline import build_baseline
from vulnpipe.ci.sla import (
    SlaError,
    SlaPolicy,
    evaluate_sla,
    load_sla_policy,
    render_sla_text,
    sla_policy_from_days,
    sla_result_to_payload,
)
from vulnpipe.core.models import Finding, Severity
from vulnpipe.processing.normalizer import make_finding

_POLICY = SlaPolicy(max_age_days={Severity.CRITICAL: 7, Severity.HIGH: 30})


def _f(title: str, *, severity: Severity = Severity.HIGH, host: str = "10.0.0.5") -> Finding:
    return make_finding(source="nmap", host=host, title=title, severity=severity, plugin_id="x")


def test_flags_finding_past_its_deadline() -> None:
    finding = _f("CVE-2021-42013", severity=Severity.CRITICAL)
    baseline = build_baseline([finding], first_seen=date(2026, 1, 1))
    result = evaluate_sla([finding], baseline, _POLICY, today=date(2026, 1, 20))
    assert result.passed is False
    assert result.exit_code == 1
    assert len(result.breaches) == 1
    breach = result.breaches[0]
    assert breach.age_days == 19
    assert breach.deadline_days == 7
    assert breach.days_over == 12


def test_finding_within_deadline_passes() -> None:
    finding = _f("CVE-2021-42013", severity=Severity.CRITICAL)
    baseline = build_baseline([finding], first_seen=date(2026, 1, 1))
    result = evaluate_sla([finding], baseline, _POLICY, today=date(2026, 1, 5))
    assert result.passed is True
    assert result.tracked == 1
    assert result.breaches == ()


def test_exactly_on_the_deadline_is_not_a_breach() -> None:
    finding = _f("CVE", severity=Severity.CRITICAL)
    baseline = build_baseline([finding], first_seen=date(2026, 1, 1))
    # Age exactly 7 days == the 7-day SLA: not yet over.
    result = evaluate_sla([finding], baseline, _POLICY, today=date(2026, 1, 8))
    assert result.passed is True


def test_severity_without_a_deadline_is_ignored() -> None:
    low = _f("low finding", severity=Severity.LOW)
    baseline = build_baseline([low], first_seen=date(2020, 1, 1))  # ancient
    result = evaluate_sla([low], baseline, _POLICY, today=date(2026, 1, 1))
    assert result.passed is True
    assert result.tracked == 0  # LOW has no SLA, so it is not even tracked


def test_untracked_finding_never_breaches() -> None:
    finding = _f("CVE", severity=Severity.CRITICAL)
    baseline = build_baseline([finding])  # no first_seen recorded
    result = evaluate_sla([finding], baseline, _POLICY, today=date(2026, 6, 1))
    assert result.passed is True
    assert result.tracked == 0
    assert result.untracked == 1


def test_breaches_are_ordered_worst_then_oldest() -> None:
    crit = _f("crit", severity=Severity.CRITICAL, host="a")
    high_old = _f("high-old", severity=Severity.HIGH, host="b")
    high_new = _f("high-new", severity=Severity.HIGH, host="c")
    baseline = build_baseline([crit], first_seen=date(2026, 1, 1))
    from vulnpipe.ci.baseline import merge_baseline

    baseline = merge_baseline(baseline, [high_old], first_seen=date(2025, 1, 1))
    baseline = merge_baseline(baseline, [high_new], first_seen=date(2026, 1, 15))
    # today - 2026-01-15 = 45d > the 30d High SLA, so high-new also breaches (but younger).
    result = evaluate_sla([crit, high_new, high_old], baseline, _POLICY, today=date(2026, 3, 1))
    # Critical first (worst severity), then the older High before the newer High.
    assert [b.finding.title for b in result.breaches] == ["crit", "high-old", "high-new"]


def test_policy_from_days_drops_unset() -> None:
    policy = sla_policy_from_days({Severity.CRITICAL: 7, Severity.HIGH: None})
    assert policy.deadline_for(Severity.CRITICAL) == 7
    assert policy.deadline_for(Severity.HIGH) is None


def test_policy_describe() -> None:
    assert _POLICY.describe() == "critical <= 7d; high <= 30d"
    assert SlaPolicy().describe() == "no SLAs (permit all)"


def test_payload_and_text_render() -> None:
    finding = _f("CVE-2021-42013", severity=Severity.CRITICAL)
    baseline = build_baseline([finding], first_seen=date(2026, 1, 1))
    result = evaluate_sla([finding], baseline, _POLICY, today=date(2026, 1, 20))
    payload = sla_result_to_payload(result)
    assert payload["passed"] is False
    assert payload["breaches"][0]["days_over"] == 12
    assert payload["breaches"][0]["first_seen"] == "2026-01-01"
    text = render_sla_text(result)
    assert "SLA breached" in text
    assert "12d over" in text and "first seen 2026-01-01" in text


def test_load_policy(tmp_path: Path) -> None:
    path = tmp_path / "sla.yaml"
    path.write_text("max_age_days:\n  critical: 7\n  high: 30\n", encoding="utf-8")
    policy = load_sla_policy(path)
    assert policy.deadline_for(Severity.CRITICAL) == 7


def test_load_missing_policy_raises(tmp_path: Path) -> None:
    with pytest.raises(SlaError, match="not found"):
        load_sla_policy(tmp_path / "nope.yaml")
