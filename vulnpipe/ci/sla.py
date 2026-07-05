"""Remediation SLAs over finding age: how long an open issue may linger.

The gate and policy layers judge whether a *new* finding should block a build. This
layer answers the complementary vulnerability-management question: has an *accepted*
(baselined) finding stayed open past its remediation deadline? A :class:`SlaPolicy`
declares a per-severity budget in days ("a Critical must be fixed within 7 days, a
High within 30"), and :func:`evaluate_sla` flags every current finding whose age --
measured from the ``first_seen`` date recorded in the baseline -- exceeds it.

Everything here is pure and deterministic: findings + baseline + policy + an
evaluation date in, an :class:`SlaResult` out, with breaches reported worst-first.
The evaluation date is injected (``today``) rather than read from the wall clock, so
tests pin it and CI can evaluate "as of" any date. A finding with no recorded
``first_seen`` (a brand-new finding, or an age-untracked baseline) is counted as
*untracked* and never breaches -- its age is unknown, and unknown is never a
violation.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Annotated, Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from vulnpipe.ci.baseline import Baseline
from vulnpipe.core.models import Finding, Severity


class SlaError(Exception):
    """Raised when an SLA policy file cannot be loaded or fails validation."""


class SlaPolicy(BaseModel):
    """Per-severity remediation deadlines, in days.

    A severity with no entry has no SLA (it never breaches). An all-default instance
    imposes no SLAs at all.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_age_days: dict[Severity, Annotated[int, Field(ge=0)]] = Field(default_factory=dict)

    def deadline_for(self, severity: Severity) -> int | None:
        """The remediation deadline (days) for ``severity``, or ``None`` if unset."""
        return self.max_age_days.get(severity)

    def describe(self) -> str:
        """A compact, deterministic one-line description of the active SLAs."""
        if not self.max_age_days:
            return "no SLAs (permit all)"
        return "; ".join(
            f"{severity.value} <= {self.max_age_days[severity]}d"
            for severity in sorted(self.max_age_days, key=lambda s: -s.rank)
        )


def load_sla_policy(path: str | Path) -> SlaPolicy:
    """Load and validate an SLA-policy YAML file (a ``max_age_days`` mapping).

    An empty file yields the permissive default policy. Raises :class:`SlaError`
    when the file is missing, unparseable, or fails schema validation.
    """
    policy_path = Path(path)
    if not policy_path.is_file():
        raise SlaError(f"SLA policy file not found: {policy_path}")
    try:
        raw = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise SlaError(f"Failed to parse SLA policy {policy_path}: {exc}") from exc
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise SlaError(f"SLA policy root must be a mapping, got {type(raw).__name__}")
    try:
        return SlaPolicy.model_validate(raw)
    except ValidationError as exc:
        raise SlaError(f"Invalid SLA policy in {policy_path}:\n{exc}") from exc


def sla_policy_from_days(days: dict[Severity, int | None]) -> SlaPolicy:
    """Build an :class:`SlaPolicy` from a mapping, dropping unset (``None``) budgets.

    Lets the CLI express inline ``--critical-days`` / ``--high-days`` options as a
    policy so both forms share one evaluation path.
    """
    budgets = {severity: value for severity, value in days.items() if value is not None}
    return SlaPolicy(max_age_days=budgets)


@dataclass(frozen=True)
class SlaBreach:
    """One finding open past its remediation deadline."""

    finding: Finding
    first_seen: date
    age_days: int
    deadline_days: int

    @property
    def days_over(self) -> int:
        """How many days past the deadline the finding is."""
        return self.age_days - self.deadline_days


@dataclass(frozen=True)
class SlaResult:
    """The outcome of evaluating an :class:`SlaPolicy` against current findings."""

    passed: bool
    policy: SlaPolicy
    breaches: tuple[SlaBreach, ...]
    tracked: int
    untracked: int

    @property
    def exit_code(self) -> int:
        """``0`` when nothing has breached its SLA, ``1`` otherwise."""
        return 0 if self.passed else 1

    @property
    def criteria(self) -> str:
        """The active SLAs, for log lines and reports."""
        return self.policy.describe()

    @property
    def summary(self) -> str:
        """A short, human-readable description of the SLA outcome."""
        if self.passed:
            return (
                f"SLA ok: no findings past their remediation deadline "
                f"({self.tracked} tracked, {self.untracked} untracked)"
            )
        return (
            f"SLA breached: {len(self.breaches)} finding(s) past their remediation "
            f"deadline ({self.tracked} tracked, {self.untracked} untracked)"
        )


def evaluate_sla(
    findings: Iterable[Finding],
    baseline: Baseline,
    policy: SlaPolicy,
    *,
    today: date,
) -> SlaResult:
    """Flag current ``findings`` open past their per-severity SLA (see the module docstring).

    A finding is judged only when its severity has a deadline *and* the baseline
    records a ``first_seen`` date for it. Its age is ``today - first_seen`` in whole
    days; older than the deadline is a breach. Breaches are reported worst-severity
    then oldest first, then by fingerprint, so the result is deterministic.
    """
    breaches: list[SlaBreach] = []
    tracked = 0
    untracked = 0
    for finding in findings:
        deadline = policy.deadline_for(finding.severity)
        if deadline is None:
            continue
        first_seen = baseline.first_seen(finding.fingerprint)
        if first_seen is None:
            untracked += 1
            continue
        tracked += 1
        age = (today - first_seen).days
        if age > deadline:
            breaches.append(
                SlaBreach(
                    finding=finding,
                    first_seen=first_seen,
                    age_days=age,
                    deadline_days=deadline,
                )
            )
    breaches.sort(key=lambda b: (-b.finding.severity.rank, -b.age_days, b.finding.fingerprint))
    return SlaResult(
        passed=not breaches,
        policy=policy,
        breaches=tuple(breaches),
        tracked=tracked,
        untracked=untracked,
    )


def sla_result_to_payload(result: SlaResult) -> dict[str, Any]:
    """Serialize an :class:`SlaResult` into a deterministic JSON-ready mapping."""
    return {
        "passed": result.passed,
        "exit_code": result.exit_code,
        "criteria": result.criteria,
        "summary": result.summary,
        "tracked": result.tracked,
        "untracked": result.untracked,
        "breaches": [
            {
                "fingerprint": breach.finding.fingerprint,
                "severity": breach.finding.severity.value,
                "title": breach.finding.title,
                "host": breach.finding.host,
                "first_seen": breach.first_seen.isoformat(),
                "age_days": breach.age_days,
                "deadline_days": breach.deadline_days,
                "days_over": breach.days_over,
            }
            for breach in result.breaches
        ],
    }


def render_sla_text(result: SlaResult) -> str:
    """Render an :class:`SlaResult` as a deterministic plain-text report."""
    lines = [f"vulnpipe SLA report — {result.criteria}", result.summary]
    for breach in result.breaches:
        finding = breach.finding
        host = finding.host if finding.port is None else f"{finding.host}:{finding.port}"
        lines.append(
            f"  ! [{finding.severity.value}] {finding.title} ({host}) — "
            f"{breach.age_days}d old, SLA {breach.deadline_days}d "
            f"({breach.days_over}d over, first seen {breach.first_seen.isoformat()})"
        )
    return "\n".join(lines) + "\n"


__all__ = [
    "SlaBreach",
    "SlaError",
    "SlaPolicy",
    "SlaResult",
    "evaluate_sla",
    "load_sla_policy",
    "render_sla_text",
    "sla_policy_from_days",
    "sla_result_to_payload",
]
