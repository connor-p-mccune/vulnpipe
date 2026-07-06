"""Markdown report renderer.

Renders findings as GitHub-flavored Markdown -- the format that drops straight into
a pull-request comment, a GitHub issue, a Slack message, or a job summary. It leads
with a one-line headline (totals, severity breakdown, and how many findings are
known-exploited), a compact severity table, and a prioritized findings table
carrying the composite risk score, CVSS, EPSS, and a KEV marker.

Like the other reporters it is pure and **deterministic for fixed input**: findings
are emitted in the order given (the prioritized order), severities appear in a fixed
worst-to-least order, and no wall-clock timestamp is embedded. Table cells are
escaped so a pipe or newline in scanner evidence can never break the table layout.
"""

from collections.abc import Iterable

from vulnpipe import __version__
from vulnpipe.core.models import Finding, Severity
from vulnpipe.reporting.base import BaseReporter
from vulnpipe.reporting.summary import (
    SEVERITY_DISPLAY_ORDER,
    OwnerGroup,
    ReportSummary,
    StandardsSummary,
    group_by_owner,
    owners_present,
    summarize,
    summarize_standards,
)

_TITLE = "vulnpipe security report"

#: Per-severity Markdown label: a colored dot (matching the HTML palette) plus a
#: word, so a rendered report is scannable at a glance on GitHub or Slack.
_SEVERITY_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "🟣 Critical",
    Severity.HIGH: "🔴 High",
    Severity.MEDIUM: "🟠 Medium",
    Severity.LOW: "🟡 Low",
    Severity.INFORMATIONAL: "🔵 Info",
}


def _escape_cell(value: str) -> str:
    """Make ``value`` safe inside a Markdown table cell (no layout-breaking chars)."""
    return " ".join(value.split()).replace("\\", "\\\\").replace("|", "\\|")


def _format_cvss(score: float | None) -> str:
    return f"{score:.1f}" if score is not None else "—"


def _format_epss(score: float | None) -> str:
    return f"{score * 100:.1f}%" if score is not None else "—"


def _host_label(finding: Finding) -> str:
    return finding.host if finding.port is None else f"{finding.host}:{finding.port}"


def _summary_line(summary: ReportSummary, kev_count: int) -> str:
    hosts = "host" if summary.host_count == 1 else "hosts"
    breakdown = ", ".join(
        f"{summary.by_severity[severity]} {severity.value}" for severity in SEVERITY_DISPLAY_ORDER
    )
    line = f"**{summary.total} findings across {summary.host_count} {hosts}** — {breakdown}"
    if kev_count:
        line += f" · ⚠️ **{kev_count} known-exploited (KEV)**"
    return line


def _severity_table(summary: ReportSummary) -> list[str]:
    rows = ["| Severity | Count |", "| --- | ---: |"]
    for severity in SEVERITY_DISPLAY_ORDER:
        rows.append(f"| {_SEVERITY_LABEL[severity]} | {summary.by_severity[severity]} |")
    return rows


def _owasp_table(standards: StandardsSummary) -> list[str]:
    """The OWASP Top 10 breakdown table (nonzero categories, rank order)."""
    rows = ["| OWASP Top 10 (2021) | Findings |", "| --- | ---: |"]
    for category, count in standards.owasp.items():
        if count:
            rows.append(f"| {category.label} | {count} |")
    if standards.uncategorized:
        rows.append(f"| _Not mapped_ | {standards.uncategorized} |")
    return rows


def _owner_table(groups: list[OwnerGroup]) -> list[str]:
    """The ownership routing table: findings per owning team/queue, worst first."""
    rows = ["| Owner | Findings | Worst |", "| --- | ---: | --- |"]
    for group in groups:
        label = _escape_cell(group.owner) if group.assigned else "_Unassigned_"
        rows.append(f"| {label} | {len(group.findings)} | {_SEVERITY_LABEL[group.highest]} |")
    return rows


def _findings_table(findings: list[Finding]) -> list[str]:
    rows = [
        "| # | Severity | Risk | Source | Host | Finding | CVSS | EPSS | Exploited |",
        "| ---: | --- | ---: | --- | --- | --- | ---: | ---: | :---: |",
    ]
    for index, finding in enumerate(findings, start=1):
        exploited = "⚠️ **Yes**" if finding.kev else "—"
        rows.append(
            f"| {index} "
            f"| {_SEVERITY_LABEL[finding.severity]} "
            f"| {finding.risk_score} "
            f"| {_escape_cell(finding.source)} "
            f"| {_escape_cell(_host_label(finding))} "
            f"| {_escape_cell(finding.title)} "
            f"| {_format_cvss(finding.cvss_score)} "
            f"| {_format_epss(finding.epss_score)} "
            f"| {exploited} |"
        )
    return rows


def render_markdown(findings: Iterable[Finding]) -> str:
    """Render ``findings`` into a GitHub-flavored Markdown report string."""
    items = list(findings)
    summary = summarize(items)
    kev_count = sum(1 for finding in items if finding.kev)

    lines = [f"# {_TITLE}", "", _summary_line(summary, kev_count), "", "## Severity summary", ""]
    lines.extend(_severity_table(summary))
    standards = summarize_standards(items)
    if standards.any_mapped:
        lines.extend(["", "## OWASP Top 10", ""])
        lines.extend(_owasp_table(standards))
    if owners_present(items):
        lines.extend(["", "## Ownership", ""])
        lines.extend(_owner_table(group_by_owner(items)))
    lines.extend(["", "## Findings", ""])
    if items:
        lines.extend(_findings_table(items))
    else:
        lines.append("_No findings._")
    footer = f"<sub>Generated by vulnpipe {__version__} — detection & reporting only.</sub>"
    lines.extend(["", footer])
    return "\n".join(lines) + "\n"


class MarkdownReporter(BaseReporter):
    """Render findings into a deterministic GitHub-flavored Markdown report."""

    name = "markdown"

    def render(self, findings: list[Finding]) -> str:
        return render_markdown(findings)


__all__ = [
    "MarkdownReporter",
    "render_markdown",
]
