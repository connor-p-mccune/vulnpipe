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


def _md_cell(value: str) -> str:
    """Escape a value for a Markdown table cell (no layout-breaking characters)."""
    return " ".join(value.split()).replace("\\", "\\\\").replace("|", "\\|")


def render_diff_markdown(diff: Diff, *, title: str = "vulnpipe scan delta") -> str:
    """Render a :class:`Diff` as a GitHub-flavored Markdown comment.

    Leads with a headline (new / persisting / resolved counts), then tables the
    newly introduced findings (worst first, the ones a reviewer must act on) and
    lists the resolved ones. Deterministic for fixed input -- buckets keep the
    diff's order and no timestamp is embedded -- and cells are escaped, so it drops
    straight into a pull-request comment or a job summary.
    """
    counts = diff.counts
    headline = (
        f"**{counts['new']} new**, {counts['persisting']} persisting, "
        f"{counts['resolved']} resolved"
    )
    verdict = "✅ No new findings." if diff.is_clean else f"⚠️ {counts['new']} new finding(s)."
    lines = [f"## {title}", "", f"{headline} — {verdict}"]

    if diff.new:
        lines.extend(
            [
                "",
                "### New findings",
                "",
                "| Severity | Risk | Host | Finding |",
                "| --- | ---: | --- | --- |",
            ]
        )
        for finding in diff.new:
            host = finding.host if finding.port is None else f"{finding.host}:{finding.port}"
            marker = " ⚠️" if finding.kev else ""
            lines.append(
                f"| {finding.severity.value}{marker} | {finding.risk_score} "
                f"| {_md_cell(host)} | {_md_cell(finding.title)} |"
            )

    if diff.resolved:
        lines.extend(["", "### Resolved findings", ""])
        for entry in diff.resolved:
            lines.append(
                f"- [{entry.severity.value}] {_md_cell(entry.title)} ({_md_cell(entry.host)})"
            )

    return "\n".join(lines) + "\n"


__all__ = [
    "Diff",
    "diff_findings",
    "diff_to_payload",
    "render_diff_markdown",
]
