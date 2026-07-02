"""The CI failure gate: fail the build on newly introduced severe findings.

The gate inspects the **new** findings from a :class:`~vulnpipe.ci.differ.Diff`
(those absent from the baseline) and fails when any of them meets or exceeds a
configured severity threshold (High by default) *or*, optionally, a composite
risk-score threshold. Persisting findings -- already in the baseline, i.e. reviewed
and accepted -- never trip the gate; that is the whole point of a baseline. The
decision is exposed as a process :attr:`GateResult.exit_code` so a CI job exits
non-zero exactly when a regression is introduced.

Pure function: a diff and the thresholds in, a :class:`GateResult` out. Deterministic
for fixed input -- the triggering findings keep the diff's (prioritized) order.
"""

from dataclasses import dataclass

from vulnpipe.ci.differ import Diff
from vulnpipe.core.models import Finding, Severity

#: Default severity at (or above) which a new finding fails the gate.
DEFAULT_GATE_SEVERITY = Severity.HIGH


def meets_threshold(finding: Finding, threshold: Severity) -> bool:
    """Whether ``finding`` is at least as severe as ``threshold``."""
    return finding.severity.rank >= threshold.rank


def _triggers(finding: Finding, threshold: Severity, min_risk_score: int | None) -> bool:
    """Whether a new finding trips the gate on severity or (if set) risk score."""
    if meets_threshold(finding, threshold):
        return True
    return min_risk_score is not None and finding.risk_score >= min_risk_score


@dataclass(frozen=True)
class GateResult:
    """The outcome of evaluating the gate against a diff."""

    passed: bool
    threshold: Severity
    #: The new findings that tripped the gate (empty when the gate passes).
    triggering: tuple[Finding, ...]
    #: The risk-score threshold applied, or ``None`` when only severity was used.
    min_risk_score: int | None = None

    @property
    def exit_code(self) -> int:
        """``0`` when the gate passes, ``1`` when a new finding tripped it."""
        return 0 if self.passed else 1

    @property
    def criteria(self) -> str:
        """The gate criteria as text, for log lines and JUnit failure bodies."""
        criteria = f"at or above {self.threshold.value}"
        if self.min_risk_score is not None:
            criteria += f" or risk >= {self.min_risk_score}"
        return criteria

    @property
    def summary(self) -> str:
        """A short, human-readable description of the gate outcome."""
        if self.passed:
            return f"gate passed: no new findings {self.criteria}"
        return f"gate failed: {len(self.triggering)} new finding(s) {self.criteria}"


def evaluate_gate(
    diff: Diff,
    *,
    threshold: Severity = DEFAULT_GATE_SEVERITY,
    min_risk_score: int | None = None,
) -> GateResult:
    """Evaluate the gate over a diff's new findings.

    The gate fails (``passed=False``, ``exit_code=1``) when at least one *new* finding
    is at or above ``threshold`` or, when ``min_risk_score`` is given, has a composite
    risk score at or above it. Only new findings are considered -- persisting
    (baselined) findings are exempt.
    """
    triggering = tuple(
        finding for finding in diff.new if _triggers(finding, threshold, min_risk_score)
    )
    return GateResult(
        passed=not triggering,
        threshold=threshold,
        triggering=triggering,
        min_risk_score=min_risk_score,
    )


__all__ = [
    "DEFAULT_GATE_SEVERITY",
    "GateResult",
    "evaluate_gate",
    "meets_threshold",
]
