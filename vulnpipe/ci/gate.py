"""The CI failure gate: fail the build on newly introduced severe findings.

The gate inspects the **new** findings from a :class:`~vulnpipe.ci.differ.Diff`
(those absent from the baseline) and fails when any of them meets or exceeds a
configured severity threshold (High by default). Persisting findings -- already in
the baseline, i.e. reviewed and accepted -- never trip the gate; that is the whole
point of a baseline. The decision is exposed as a process :attr:`GateResult.exit_code`
so a CI job exits non-zero exactly when a regression is introduced.

Pure function: a diff and a threshold in, a :class:`GateResult` out. Deterministic
for fixed input -- the triggering findings keep the diff's (prioritized) order.
"""

from collections.abc import Iterable
from dataclasses import dataclass

from vulnpipe.ci.differ import Diff
from vulnpipe.core.models import Finding, Severity

#: Default severity at (or above) which a new finding fails the gate.
DEFAULT_GATE_SEVERITY = Severity.HIGH


def meets_threshold(finding: Finding, threshold: Severity) -> bool:
    """Whether ``finding`` is at least as severe as ``threshold``."""
    return finding.severity.rank >= threshold.rank


def _triggering(findings: Iterable[Finding], threshold: Severity) -> tuple[Finding, ...]:
    return tuple(finding for finding in findings if meets_threshold(finding, threshold))


@dataclass(frozen=True)
class GateResult:
    """The outcome of evaluating the gate against a diff."""

    passed: bool
    threshold: Severity
    #: The new findings at or above the threshold (empty when the gate passes).
    triggering: tuple[Finding, ...]

    @property
    def exit_code(self) -> int:
        """``0`` when the gate passes, ``1`` when a new finding tripped it."""
        return 0 if self.passed else 1

    @property
    def summary(self) -> str:
        """A short, human-readable description of the gate outcome."""
        if self.passed:
            return f"gate passed: no new findings at or above {self.threshold.value}"
        return (
            f"gate failed: {len(self.triggering)} new finding(s) "
            f"at or above {self.threshold.value}"
        )


def evaluate_gate(diff: Diff, *, threshold: Severity = DEFAULT_GATE_SEVERITY) -> GateResult:
    """Evaluate the gate over a diff's new findings against ``threshold``.

    The gate fails (``passed=False``, ``exit_code=1``) when at least one *new*
    finding is at or above ``threshold``; otherwise it passes. Only new findings
    are considered -- persisting (baselined) findings are exempt.
    """
    triggering = _triggering(diff.new, threshold)
    return GateResult(passed=not triggering, threshold=threshold, triggering=triggering)


__all__ = [
    "DEFAULT_GATE_SEVERITY",
    "GateResult",
    "evaluate_gate",
    "meets_threshold",
]
