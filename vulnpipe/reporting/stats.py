"""Terminal statistics view for a findings report.

Renders a compact, at-a-glance summary of a set of findings for the console: the
headline totals, a severity breakdown, the highest-risk findings, and the worst
affected hosts. This is the human "what does this scan look like" view that backs
the ``vulnpipe stats`` command, as distinct from the machine-readable report
formats in the sibling reporter modules.

:func:`render_stats` is a pure ``findings -> str`` function -- it renders through a
fixed-width, non-terminal Rich console into a string -- so it is deterministic for
fixed input and unit-testable without a real terminal.
"""

import io
from collections.abc import Iterable
from typing import Any

from rich.console import Console
from rich.table import Table

from vulnpipe.core.models import Finding, Severity
from vulnpipe.reporting.remediation import plan_remediations
from vulnpipe.reporting.summary import (
    SEVERITY_DISPLAY_ORDER,
    StandardsSummary,
    group_by_host,
    summarize,
    summarize_standards,
)

#: Fixed render width so the string output is stable regardless of the real terminal.
_WIDTH = 100
#: How many rows the "top" tables show at most.
_TOP_N = 10

# Rich color per severity (mirrors the HTML palette closely enough for a terminal).
_SEVERITY_COLOR = {
    "critical": "magenta",
    "high": "red",
    "medium": "dark_orange",
    "low": "yellow",
    "informational": "blue",
}


def _severity_cell(value: str) -> str:
    return f"[{_SEVERITY_COLOR.get(value, 'white')}]{value}[/]"


def _host_label(finding: Finding) -> str:
    return finding.host if finding.port is None else f"{finding.host}:{finding.port}"


def _severity_table(by_severity: dict[Severity, int]) -> Table:
    table = Table(title="By severity", title_justify="left", expand=False)
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for severity in SEVERITY_DISPLAY_ORDER:
        table.add_row(_severity_cell(severity.value), str(by_severity[severity]))
    return table


def _owasp_table(standards: StandardsSummary) -> Table:
    table = Table(title="OWASP Top 10 (2021)", title_justify="left", expand=False)
    table.add_column("Category")
    table.add_column("Findings", justify="right")
    for category, count in standards.owasp.items():
        if count:
            table.add_row(category.label, str(count))
    if standards.uncategorized:
        table.add_row("[dim]not mapped[/]", str(standards.uncategorized))
    return table


def _top_risks_table(findings: list[Finding]) -> Table:
    ranked = sorted(findings, key=lambda finding: (-finding.risk_score, finding.fingerprint))
    table = Table(title=f"Top {_TOP_N} by risk", title_justify="left", expand=False)
    table.add_column("#", justify="right")
    table.add_column("Risk", justify="right")
    table.add_column("Severity")
    table.add_column("KEV", justify="center")
    table.add_column("Host")
    table.add_column("Finding")
    for index, finding in enumerate(ranked[:_TOP_N], start=1):
        table.add_row(
            str(index),
            str(finding.risk_score),
            _severity_cell(finding.severity.value),
            "[red]!" if finding.kev else "",
            _host_label(finding),
            finding.title,
        )
    return table


def _top_hosts_table(findings: list[Finding]) -> Table:
    groups = group_by_host(findings)
    table = Table(title=f"Top {_TOP_N} hosts", title_justify="left", expand=False)
    table.add_column("Host")
    table.add_column("Findings", justify="right")
    table.add_column("Worst")
    for group in groups[:_TOP_N]:
        table.add_row(
            group.host,
            str(len(group.findings)),
            _severity_cell(group.highest.value),
        )
    return table


def _remediation_table(findings: list[Finding]) -> Table:
    actions = plan_remediations(findings)
    table = Table(title=f"Top {_TOP_N} remediations", title_justify="left", expand=False)
    table.add_column("#", justify="right")
    table.add_column("Risk", justify="right")
    table.add_column("Fixes", justify="right")
    table.add_column("Worst")
    table.add_column("KEV", justify="center")
    table.add_column("Action")
    for index, action in enumerate(actions[:_TOP_N], start=1):
        table.add_row(
            str(index),
            str(action.total_risk),
            str(action.count),
            _severity_cell(action.highest.value),
            "[red]!" if action.kev else "",
            action.title,
        )
    return table


def render_stats(findings: Iterable[Finding]) -> str:
    """Render a deterministic, plain-text statistics summary for ``findings``."""
    items = list(findings)
    summary = summarize(items)
    kev_count = sum(1 for finding in items if finding.kev)

    buffer = io.StringIO()
    console = Console(file=buffer, width=_WIDTH, force_terminal=False, highlight=False)
    hosts = "host" if summary.host_count == 1 else "hosts"
    console.print(f"vulnpipe — {summary.total} findings across {summary.host_count} {hosts}")
    if kev_count:
        console.print(f"[red]{kev_count} known-exploited (in the CISA KEV catalog)[/]")
    console.print(_severity_table(summary.by_severity))
    standards = summarize_standards(items)
    if standards.any_mapped:
        console.print(_owasp_table(standards))
    if items:
        console.print(_top_risks_table(items))
        console.print(_top_hosts_table(items))
        console.print(_remediation_table(items))
    else:
        console.print("No findings.")
    return buffer.getvalue()


def stats_to_payload(findings: Iterable[Finding]) -> dict[str, Any]:
    """Build a compact, deterministic dashboard summary of ``findings``.

    The machine-readable counterpart to :func:`render_stats`: totals, the severity
    breakdown, known-exploited count, the OWASP / CWE Top 25 distribution, the top
    findings by risk, the worst-affected hosts, and the remediation-plan size -- the
    numbers a dashboard needs without parsing every finding.
    """
    items = list(findings)
    summary = summarize(items)
    standards = summarize_standards(items)
    ranked = sorted(items, key=lambda finding: (-finding.risk_score, finding.fingerprint))
    groups = group_by_host(items)
    actions = plan_remediations(items)
    return {
        "total": summary.total,
        "hosts": summary.host_count,
        "kev": sum(1 for finding in items if finding.kev),
        "by_severity": {
            severity.value: summary.by_severity[severity] for severity in SEVERITY_DISPLAY_ORDER
        },
        "owasp": {category.short: count for category, count in standards.owasp.items() if count},
        "cwe_top_25": standards.cwe_top_25,
        "top_risks": [
            {
                "risk_score": finding.risk_score,
                "severity": finding.severity.value,
                "kev": finding.kev,
                "host": finding.host,
                "title": finding.title,
                "fingerprint": finding.fingerprint,
            }
            for finding in ranked[:_TOP_N]
        ],
        "worst_hosts": [
            {"host": group.host, "findings": len(group.findings), "highest": group.highest.value}
            for group in groups[:_TOP_N]
        ],
        "remediation": {
            "actions": len(actions),
            "findings": sum(action.count for action in actions),
        },
    }


__all__ = ["render_stats", "stats_to_payload"]
