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
from html import escape
from typing import Any

from vulnpipe.ci.baseline import Baseline, BaselineEntry
from vulnpipe.core.models import Finding, Severity


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


# Severity -> CSS class for the HTML diff chips; mirrors the report palette so a
# diff page reads on the same colors as the full HTML report.
_SEVERITY_CSS: dict[Severity, str] = {
    Severity.CRITICAL: "sev-critical",
    Severity.HIGH: "sev-high",
    Severity.MEDIUM: "sev-medium",
    Severity.LOW: "sev-low",
    Severity.INFORMATIONAL: "sev-informational",
}

_DIFF_HTML_STYLE = """
body { font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  margin: 2rem; color: #1a1a1a; }
h1 { font-size: 1.4rem; margin-bottom: .25rem; }
h2 { margin-top: 1.75rem; font-size: 1.1rem; }
.verdict { font-size: 1rem; font-weight: 600; }
.verdict.clean { color: #2e7d32; }
.verdict.dirty { color: #c62828; }
table { border-collapse: collapse; width: 100%; margin-top: .5rem; }
th, td { text-align: left; padding: .35rem .6rem; border-bottom: 1px solid #e0e0e0;
  font-size: .9rem; }
th { background: #fafafa; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
.chip { display: inline-block; padding: .05rem .55rem; border-radius: 10px;
  color: #fff; font-size: .78rem; }
.sev-critical { background: #7b1fa2; } .sev-high { background: #c62828; }
.sev-medium { background: #ef6c00; } .sev-low { background: #f9a825; }
.sev-informational { background: #1565c0; }
.kev { color: #c62828; font-weight: 700; }
.muted { color: #666; }
""".strip()


def _host_label(host: str, port: int | None) -> str:
    """``host`` or ``host:port`` for display."""
    return host if port is None else f"{host}:{port}"


def _sev_chip(severity: Severity) -> str:
    """An escaped severity chip ``<span>`` for the HTML diff."""
    return f'<span class="chip {_SEVERITY_CSS[severity]}">{escape(severity.value)}</span>'


def render_diff_html(diff: Diff, *, title: str = "vulnpipe scan delta") -> str:
    """Render a :class:`Diff` as a self-contained, shareable HTML page.

    Leads with the new/persisting/resolved headline and verdict, then tables the
    newly introduced findings (worst first), the resolved ones, and the persisting
    ones behind a disclosure. Deterministic for fixed input -- buckets keep the
    diff's order and no timestamp is embedded -- and every value is HTML-escaped
    (a reflected ``<script>`` title renders as inert text), so the page is safe to
    open or publish as a build artifact.
    """
    counts = diff.counts
    verdict_class = "clean" if diff.is_clean else "dirty"
    verdict = "No new findings." if diff.is_clean else f"{counts['new']} new finding(s) introduced."
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{escape(title)}</title>",
        f"<style>{_DIFF_HTML_STYLE}</style>",
        "</head>",
        "<body>",
        f"<h1>{escape(title)}</h1>",
        (
            f'<p class="verdict {verdict_class}">'
            f"{counts['new']} new · {counts['persisting']} persisting · "
            f"{counts['resolved']} resolved — {escape(verdict)}</p>"
        ),
    ]

    if diff.new:
        parts.append("<h2>New findings</h2>")
        parts.append("<table><thead><tr>")
        parts.append("<th>Severity</th><th>Risk</th><th>Host</th><th>Finding</th><th>CVEs</th>")
        parts.append("</tr></thead><tbody>")
        for finding in diff.new:
            kev = ' <span class="kev" title="Known exploited (CISA KEV)">&#9888;</span>'
            parts.append(
                "<tr>"
                f"<td>{_sev_chip(finding.severity)}{kev if finding.kev else ''}</td>"
                f'<td class="num">{finding.risk_score}</td>'
                f"<td>{escape(_host_label(finding.host, finding.port))}</td>"
                f"<td>{escape(finding.title)}</td>"
                f"<td>{escape(', '.join(finding.cve_ids))}</td>"
                "</tr>"
            )
        parts.append("</tbody></table>")

    if diff.resolved:
        parts.append("<h2>Resolved findings</h2>")
        parts.append("<table><thead><tr><th>Severity</th><th>Host</th><th>Finding</th>")
        parts.append("</tr></thead><tbody>")
        for entry in diff.resolved:
            parts.append(
                "<tr>"
                f"<td>{_sev_chip(entry.severity)}</td>"
                f"<td>{escape(_host_label(entry.host, entry.port))}</td>"
                f"<td>{escape(entry.title)}</td>"
                "</tr>"
            )
        parts.append("</tbody></table>")

    if diff.persisting:
        parts.append(
            f"<h2>Persisting findings <span class='muted'>({counts['persisting']})</span></h2>"
        )
        parts.append("<details><summary>Show already-known findings</summary>")
        parts.append("<table><thead><tr><th>Severity</th><th>Host</th><th>Finding</th>")
        parts.append("</tr></thead><tbody>")
        for finding in diff.persisting:
            parts.append(
                "<tr>"
                f"<td>{_sev_chip(finding.severity)}</td>"
                f"<td>{escape(_host_label(finding.host, finding.port))}</td>"
                f"<td>{escape(finding.title)}</td>"
                "</tr>"
            )
        parts.append("</tbody></table></details>")

    parts.extend(["</body>", "</html>", ""])
    return "\n".join(parts)


__all__ = [
    "Diff",
    "diff_findings",
    "diff_to_payload",
    "render_diff_html",
    "render_diff_markdown",
]
