"""Policy-as-code for the CI gate: budgets and blocks expressed in YAML.

The plain severity gate (:mod:`vulnpipe.ci.gate`) answers one question -- "is any
*new* finding at or above a severity?". Real gating policies are richer: teams
tolerate a bounded number of new Mediums, refuse any new known-exploited (KEV)
finding regardless of severity, or cap the composite risk score. A
:class:`GatePolicy` captures those rules declaratively in a reviewable YAML file
(see ``configs/policy.example.yaml``), and :func:`evaluate_policy` applies them to
a baseline diff.

Like the severity gate, only **new** findings are judged -- persisting (baselined)
findings never violate a policy; that is the point of a baseline. Everything here
is pure and deterministic: a diff and a policy in, a :class:`PolicyResult` out,
with violations reported in a fixed rule order and findings kept in the diff's
(prioritized) order. An empty policy permits everything.

Rules:

* ``max_new`` -- per-severity budgets for new findings. ``critical: 0`` means "no
  new criticals"; a severity with no budget is unlimited.
* ``max_new_total`` -- a cap on the total number of new findings.
* ``min_risk_score`` -- any new finding whose composite risk score is at or above
  this fails (the same semantics as ``--gate-risk-score``).
* ``block_kev`` -- any new finding whose CVE is in the CISA KEV catalog (actively
  exploited) fails, regardless of severity.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from vulnpipe.ci.differ import Diff
from vulnpipe.core.models import Finding, Severity


class PolicyError(Exception):
    """Raised when a gate policy file cannot be loaded or fails validation."""


class GatePolicy(BaseModel):
    """A declarative gate policy (see the module docstring for rule semantics).

    An all-default instance permits everything: no budgets, no caps, no blocks.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_new: dict[Severity, Annotated[int, Field(ge=0)]] = Field(default_factory=dict)
    max_new_total: int | None = Field(default=None, ge=0)
    min_risk_score: int | None = Field(default=None, ge=0, le=100)
    block_kev: bool = False

    def describe(self) -> str:
        """A compact, deterministic one-line description of the active rules."""
        parts: list[str] = []
        for severity in sorted(self.max_new, key=lambda s: -s.rank):
            parts.append(f"new {severity.value} <= {self.max_new[severity]}")
        if self.max_new_total is not None:
            parts.append(f"new total <= {self.max_new_total}")
        if self.min_risk_score is not None:
            parts.append(f"risk < {self.min_risk_score}")
        if self.block_kev:
            parts.append("no new known-exploited")
        return "; ".join(parts) if parts else "no rules (permit all)"


def load_policy(path: str | Path) -> GatePolicy:
    """Load and validate a gate-policy YAML file.

    An empty file yields the permissive default policy. Raises
    :class:`PolicyError` when the file is missing, unparseable, or fails schema
    validation.
    """
    policy_path = Path(path)
    if not policy_path.is_file():
        raise PolicyError(f"Gate policy file not found: {policy_path}")
    try:
        raw = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"Failed to parse gate policy {policy_path}: {exc}") from exc
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise PolicyError(f"Gate policy root must be a mapping, got {type(raw).__name__}")
    try:
        return GatePolicy.model_validate(raw)
    except ValidationError as exc:
        raise PolicyError(f"Invalid gate policy in {policy_path}:\n{exc}") from exc


def policy_from_threshold(threshold: Severity, *, min_risk_score: int | None = None) -> GatePolicy:
    """Express the plain severity gate as a policy (zero budget at/above ``threshold``).

    ``evaluate_policy`` over this policy flags exactly the findings
    :func:`vulnpipe.ci.gate.evaluate_gate` would, so callers that speak "policy" can
    also serve the simple threshold form through one code path.
    """
    budgets = {severity: 0 for severity in Severity if severity.rank >= threshold.rank}
    return GatePolicy(max_new=budgets, min_risk_score=min_risk_score)


@dataclass(frozen=True)
class PolicyViolation:
    """One violated rule, with the new findings that violated it."""

    rule: str
    detail: str
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class PolicyResult:
    """The outcome of evaluating a :class:`GatePolicy` against a diff."""

    passed: bool
    policy: GatePolicy
    violations: tuple[PolicyViolation, ...]

    @property
    def exit_code(self) -> int:
        """``0`` when the policy passes, ``1`` when any rule was violated."""
        return 0 if self.passed else 1

    @property
    def criteria(self) -> str:
        """The active rules, for log lines and JUnit failure bodies."""
        return self.policy.describe()

    @property
    def triggering(self) -> tuple[Finding, ...]:
        """The distinct findings across all violations, in first-seen order."""
        seen: dict[str, Finding] = {}
        for violation in self.violations:
            for finding in violation.findings:
                seen.setdefault(finding.fingerprint, finding)
        return tuple(seen.values())

    @property
    def summary(self) -> str:
        """A short, human-readable description of the policy outcome."""
        if self.passed:
            return f"gate passed: no policy violations ({self.criteria})"
        return (
            f"gate failed: {len(self.violations)} policy violation(s), "
            f"{len(self.triggering)} finding(s) ({self.criteria})"
        )


def _severity_violations(new: tuple[Finding, ...], policy: GatePolicy) -> list[PolicyViolation]:
    violations: list[PolicyViolation] = []
    for severity in sorted(policy.max_new, key=lambda s: -s.rank):
        budget = policy.max_new[severity]
        offenders = tuple(finding for finding in new if finding.severity is severity)
        if len(offenders) > budget:
            violations.append(
                PolicyViolation(
                    rule=f"max_new[{severity.value}]",
                    detail=(
                        f"{len(offenders)} new {severity.value} finding(s) "
                        f"exceed the budget of {budget}"
                    ),
                    findings=offenders,
                )
            )
    return violations


def evaluate_policy(diff: Diff, policy: GatePolicy) -> PolicyResult:
    """Evaluate ``policy`` over the **new** findings in ``diff``.

    Violations are reported in a fixed rule order -- severity budgets (worst band
    first), the total cap, the risk-score rule, then the KEV block -- and each
    violation carries the offending findings in the diff's (prioritized) order, so
    the result is deterministic for fixed input.
    """
    new = diff.new
    violations: list[PolicyViolation] = list(_severity_violations(new, policy))

    if policy.max_new_total is not None and len(new) > policy.max_new_total:
        violations.append(
            PolicyViolation(
                rule="max_new_total",
                detail=(
                    f"{len(new)} new finding(s) exceed the total budget "
                    f"of {policy.max_new_total}"
                ),
                findings=new,
            )
        )

    if policy.min_risk_score is not None:
        risky = tuple(finding for finding in new if finding.risk_score >= policy.min_risk_score)
        if risky:
            violations.append(
                PolicyViolation(
                    rule="min_risk_score",
                    detail=(
                        f"{len(risky)} new finding(s) at or above "
                        f"risk score {policy.min_risk_score}"
                    ),
                    findings=risky,
                )
            )

    if policy.block_kev:
        exploited = tuple(finding for finding in new if finding.kev)
        if exploited:
            violations.append(
                PolicyViolation(
                    rule="block_kev",
                    detail=(
                        f"{len(exploited)} new known-exploited (KEV) finding(s); "
                        "the policy blocks all of them"
                    ),
                    findings=exploited,
                )
            )

    return PolicyResult(passed=not violations, policy=policy, violations=tuple(violations))


def policy_result_to_payload(result: PolicyResult) -> dict[str, object]:
    """Serialize a :class:`PolicyResult` into a deterministic JSON-ready mapping.

    Findings are summarized (fingerprint, severity, title, host, risk score, KEV)
    rather than fully serialized -- the full findings live in the report JSON; this
    payload is the verdict.
    """

    def _finding(finding: Finding) -> dict[str, object]:
        return {
            "fingerprint": finding.fingerprint,
            "severity": finding.severity.value,
            "title": finding.title,
            "host": finding.host,
            "risk_score": finding.risk_score,
            "kev": finding.kev,
        }

    return {
        "passed": result.passed,
        "exit_code": result.exit_code,
        "criteria": result.criteria,
        "summary": result.summary,
        "violations": [
            {
                "rule": violation.rule,
                "detail": violation.detail,
                "findings": [_finding(finding) for finding in violation.findings],
            }
            for violation in result.violations
        ],
    }


__all__ = [
    "GatePolicy",
    "PolicyError",
    "PolicyResult",
    "PolicyViolation",
    "evaluate_policy",
    "load_policy",
    "policy_from_threshold",
    "policy_result_to_payload",
]
