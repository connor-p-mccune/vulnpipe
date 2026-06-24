"""Classify a scan against a baseline: new / persisting / resolved.

Given the current findings and a :class:`~vulnpipe.ci.baseline.Baseline`, every
finding is bucketed by comparing stable fingerprints:

* **new** -- a current finding whose fingerprint is *not* in the baseline (newly
  introduced; this is what the CI gate keys on);
* **persisting** -- a current finding whose fingerprint *is* in the baseline
  (already known and accepted);
* **resolved** -- a baseline entry whose fingerprint is *absent* from the current
  scan (the issue appears fixed). Resolved items are reported from the baseline
  snapshot since there is no current finding to describe them.

Pure function -- findings + baseline in, a :class:`Diff` out -- and deterministic
for fixed input: ``new`` and ``persisting`` keep the current (prioritized) order,
and ``resolved`` follows the baseline's stored order. This is what makes the diff
output and its snapshot tests stable across runs.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from vulnpipe.ci.baseline import Baseline, BaselineEntry
from vulnpipe.core.models import Finding


@dataclass(frozen=True)
class Diff:
    """The result of diffing current findings against a baseline."""

    new: tuple[Finding, ...]
    persisting: tuple[Finding, ...]
    resolved: tuple[BaselineEntry, ...]

    @property
    def counts(self) -> dict[str, int]:
        """The ``{bucket: count}`` summary, in new/persisting/resolved order."""
        return {
            "new": len(self.new),
            "persisting": len(self.persisting),
            "resolved": len(self.resolved),
        }

    @property
    def is_clean(self) -> bool:
        """Whether the scan introduced nothing new relative to the baseline."""
        return not self.new


def diff_findings(current: Iterable[Finding], baseline: Baseline) -> Diff:
    """Classify ``current`` findings against ``baseline`` (see the module docstring).

    ``current`` is expected to be deduplicated (one finding per fingerprint); the
    prioritized order is preserved in the ``new`` and ``persisting`` buckets.
    """
    items = list(current)
    baseline_fingerprints = baseline.fingerprints
    current_fingerprints = {finding.fingerprint for finding in items}

    new: list[Finding] = []
    persisting: list[Finding] = []
    for finding in items:
        if finding.fingerprint in baseline_fingerprints:
            persisting.append(finding)
        else:
            new.append(finding)

    resolved = tuple(
        entry for entry in baseline.entries if entry.fingerprint not in current_fingerprints
    )
    return Diff(new=tuple(new), persisting=tuple(persisting), resolved=resolved)


def diff_to_payload(diff: Diff) -> dict[str, Any]:
    """Serialize a :class:`Diff` into a deterministic JSON-ready mapping.

    Findings are emitted with their fingerprint (as in the JSON report); resolved
    items are emitted from their baseline snapshot. The bucket order is fixed.
    """
    return {
        "summary": diff.counts,
        "new": [finding.model_dump(mode="json") for finding in diff.new],
        "persisting": [finding.model_dump(mode="json") for finding in diff.persisting],
        "resolved": [entry.model_dump(mode="json") for entry in diff.resolved],
    }


__all__ = [
    "Diff",
    "diff_findings",
    "diff_to_payload",
]
