"""Remediation planning: collapse findings into a ranked, deduplicated fix list.

A report answers *what is wrong*; a remediation plan answers *what to do first*.
Many findings resolve to a single action -- three CVEs on one Apache build are
cleared by one upgrade, a dozen advisories on the same dependency by bumping it
once -- so this module groups findings by the action that fixes them and ranks
those actions by the risk they remove. That turns a long, flat findings list into
a short, ordered worklist an operator can actually execute.

Everything here is pure (findings in -> actions out) and deterministic, and it
invents nothing. An action's instruction is the scanner's own ``solution`` text
when it offered one, or a template built from the finding's product/package
metadata otherwise; when no fix is known the action says exactly that ("upgrade to
a fixed release") rather than fabricating a version. The ranking is a function of
fields already on the findings (severity, the composite risk score, KEV status),
so a plan is a re-view of the report -- not a new data source.

Grouping keys, most specific first:

* **package** -- supply-chain findings that name a dependency (``package``
  metadata) group across versions and applications: one upgrade fixes them all.
* **service** -- network findings that name a product (``product`` metadata) group
  per host: patching that service on that host clears its CVEs.
* **class** -- anything else groups by ``(source, normalized title)`` so the same
  weakness class across many endpoints (e.g. reflected XSS) becomes one entry.
"""

import io
from collections.abc import Iterable
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

from vulnpipe.core.models import Finding, Severity, normalize_title

#: Fixed render width so the text output is stable regardless of the real terminal.
_WIDTH = 100

# Rich color per severity (mirrors the stats view / HTML palette).
_SEVERITY_COLOR: dict[str, str] = {
    "critical": "magenta",
    "high": "red",
    "medium": "dark_orange",
    "low": "yellow",
    "informational": "blue",
}

#: Per-severity Markdown label: a colored dot plus a word (mirrors the Markdown report).
_SEVERITY_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "🟣 Critical",
    Severity.HIGH: "🔴 High",
    Severity.MEDIUM: "🟠 Medium",
    Severity.LOW: "🟡 Low",
    Severity.INFORMATIONAL: "🔵 Info",
}


@dataclass(frozen=True)
class RemediationAction:
    """One remediation step and the findings it resolves.

    ``findings`` keeps its incoming (prioritized) order; the aggregate properties
    are derived from it, so an action never carries a number that is not backed by
    a finding it contains.
    """

    key: str
    title: str
    detail: str
    findings: tuple[Finding, ...]

    @property
    def count(self) -> int:
        """How many findings this one action resolves."""
        return len(self.findings)

    @property
    def highest(self) -> Severity:
        """The worst severity among the resolved findings."""
        return max((finding.severity for finding in self.findings), key=lambda s: s.rank)

    @property
    def kev(self) -> bool:
        """Whether any resolved finding is known-exploited (in the CISA KEV catalog)."""
        return any(finding.kev for finding in self.findings)

    @property
    def total_risk(self) -> int:
        """The summed composite risk score removed by taking this action."""
        return sum(finding.risk_score for finding in self.findings)

    @property
    def max_risk(self) -> int:
        """The single highest composite risk score among the resolved findings."""
        return max((finding.risk_score for finding in self.findings), default=0)

    @property
    def hosts(self) -> tuple[str, ...]:
        """The distinct hosts (or SBOM subjects) this action touches, sorted."""
        return tuple(sorted({finding.host for finding in self.findings}))

    @property
    def cve_ids(self) -> tuple[str, ...]:
        """The distinct CVE ids across the resolved findings, sorted."""
        seen: dict[str, None] = {}
        for finding in self.findings:
            for cve in finding.cve_ids:
                seen.setdefault(cve, None)
        return tuple(sorted(seen))


def _meta_str(finding: Finding, key: str) -> str | None:
    """Return a non-empty stripped string from ``finding.metadata[key]``, else ``None``."""
    value = finding.metadata.get(key)
    if isinstance(value, str):
        text = value.strip()
        return text or None
    return None


def _classify(finding: Finding) -> tuple[str, str]:
    """Return the ``(kind, group_key)`` a finding belongs to (see the module docstring)."""
    package = _meta_str(finding, "package")
    if package is not None:
        return "package", f"package:{package.lower()}"
    product = _meta_str(finding, "product")
    if product is not None:
        version = _meta_str(finding, "version")
        label = product if version is None else f"{product} {version}"
        return "service", f"service:{finding.host.lower()}:{label.lower()}"
    return "class", f"class:{finding.source.lower()}:{normalize_title(finding.title)}"


def _service_label(finding: Finding) -> str:
    product = _meta_str(finding, "product") or "the affected service"
    version = _meta_str(finding, "version")
    return product if version is None else f"{product} {version}"


def _action_text(kind: str, rep: Finding, solution: str | None) -> tuple[str, str]:
    """Build the ``(title, detail)`` for a group from its representative finding.

    ``detail`` prefers the scanner's own remediation advice (``solution``); when
    none was offered it falls back to an honest template that never invents a
    specific fixed version.
    """
    if kind == "package":
        package = _meta_str(rep, "package") or rep.host
        title = f"Upgrade {package}"
        return title, solution or f"Upgrade {package} to a fixed release."
    if kind == "service":
        label = _service_label(rep)
        title = f"Patch {label} on {rep.host}"
        return title, solution or f"Apply vendor updates for {label} on {rep.host}."
    title = f"Remediate: {rep.title}"
    return title, solution or "Review the affected finding(s) and apply the appropriate fix."


def _rank(action: RemediationAction) -> tuple[int, int, int, int, str]:
    """Ascending sort key encoding the descending priority order.

    Known-exploited actions lead, then the worst severity, then the most risk
    removed, then the most findings fixed; the stable group key breaks final ties.
    """
    return (
        -int(action.kev),
        -action.highest.rank,
        -action.total_risk,
        -action.count,
        action.key,
    )


def plan_remediations(findings: Iterable[Finding]) -> list[RemediationAction]:
    """Group ``findings`` into remediation actions, most impactful first.

    Pure and deterministic: findings keep their incoming order within a group, and
    the groups are ordered by known-exploited status, worst severity, total risk
    removed, count, then a stable key. An empty input yields an empty plan.
    """
    groups: dict[str, list[Finding]] = {}
    kinds: dict[str, str] = {}
    for finding in findings:
        kind, key = _classify(finding)
        groups.setdefault(key, []).append(finding)
        kinds.setdefault(key, kind)
    actions: list[RemediationAction] = []
    for key, group in groups.items():
        solution = next((finding.solution for finding in group if finding.solution), None)
        title, detail = _action_text(kinds[key], group[0], solution)
        actions.append(
            RemediationAction(key=key, title=title, detail=detail, findings=tuple(group))
        )
    actions.sort(key=_rank)
    return actions


def _limit(actions: list[RemediationAction], top: int | None) -> list[RemediationAction]:
    return actions if top is None or top <= 0 else actions[:top]


def render_remediation_text(findings: Iterable[Finding], *, top: int | None = None) -> str:
    """Render a deterministic, fixed-width remediation plan for the console.

    Shows the headline (how many actions resolve how many findings) and a ranked
    table of the top actions with the risk each removes, the worst severity it
    clears, how many findings it fixes, a KEV marker, and the recommended step.
    """
    actions = plan_remediations(findings)
    total_findings = sum(action.count for action in actions)
    shown = _limit(actions, top)

    buffer = io.StringIO()
    console = Console(file=buffer, width=_WIDTH, force_terminal=False, highlight=False)
    plural = "action" if len(actions) == 1 else "actions"
    console.print(
        f"vulnpipe remediation plan — {len(actions)} {plural} "
        f"resolving {total_findings} finding(s)"
    )
    if not actions:
        console.print("No findings to remediate.")
        return buffer.getvalue()

    table = Table(title="Recommended actions", title_justify="left", expand=False)
    table.add_column("#", justify="right")
    table.add_column("Risk", justify="right")
    table.add_column("Worst")
    table.add_column("Fixes", justify="right")
    table.add_column("KEV", justify="center")
    table.add_column("Action")
    for index, action in enumerate(shown, start=1):
        worst = action.highest.value
        table.add_row(
            str(index),
            str(action.total_risk),
            f"[{_SEVERITY_COLOR.get(worst, 'white')}]{worst}[/]",
            str(action.count),
            "[red]!" if action.kev else "",
            action.title,
        )
    console.print(table)
    if top is not None and 0 < top < len(actions):
        console.print(f"… and {len(actions) - top} more action(s).")
    return buffer.getvalue()


def _md_cell(value: str) -> str:
    """Escape a value for a Markdown table cell (no layout-breaking characters)."""
    return " ".join(value.split()).replace("\\", "\\\\").replace("|", "\\|")


def render_remediation_markdown(findings: Iterable[Finding], *, top: int | None = None) -> str:
    """Render the remediation plan as a GitHub-flavored Markdown worklist.

    Deterministic for fixed input and fully cell-escaped, so it drops into a
    pull-request comment or a job summary alongside the diff.
    """
    actions = plan_remediations(findings)
    total_findings = sum(action.count for action in actions)
    shown = _limit(actions, top)

    lines = ["# vulnpipe remediation plan", ""]
    plural = "action" if len(actions) == 1 else "actions"
    headline = f"**{len(actions)} recommended {plural}** resolving **{total_findings} findings**."
    lines.extend([headline, ""])
    if not actions:
        lines.append("_No findings to remediate._")
        return "\n".join(lines) + "\n"

    lines.extend(
        [
            "| # | Priority | Fixes | Worst | Action | Recommendation |",
            "| ---: | ---: | ---: | --- | --- | --- |",
        ]
    )
    for index, action in enumerate(shown, start=1):
        worst = f"{_SEVERITY_LABEL[action.highest]}{' ⚠️' if action.kev else ''}"
        lines.append(
            f"| {index} | {action.total_risk} | {action.count} | {worst} "
            f"| {_md_cell(action.title)} | {_md_cell(action.detail)} |"
        )
    if top is not None and 0 < top < len(actions):
        lines.extend(["", f"_… and {len(actions) - top} more action(s)._"])
    return "\n".join(lines) + "\n"


def remediation_to_payload(
    findings: Iterable[Finding], *, top: int | None = None
) -> dict[str, object]:
    """Serialize the remediation plan into a deterministic JSON-ready mapping.

    Each action summarizes what it fixes (count, risk removed, worst severity, KEV,
    the affected hosts, the CVEs, and the resolved findings' fingerprints); the full
    findings live in the report JSON, so this payload is the worklist, not a copy.
    """
    actions = plan_remediations(findings)
    shown = _limit(actions, top)
    return {
        "summary": {
            "actions": len(actions),
            "findings": sum(action.count for action in actions),
        },
        "actions": [
            {
                "rank": index,
                "key": action.key,
                "title": action.title,
                "detail": action.detail,
                "finding_count": action.count,
                "total_risk": action.total_risk,
                "max_risk": action.max_risk,
                "highest": action.highest.value,
                "kev": action.kev,
                "hosts": list(action.hosts),
                "cve_ids": list(action.cve_ids),
                "fingerprints": [finding.fingerprint for finding in action.findings],
            }
            for index, action in enumerate(shown, start=1)
        ],
    }


__all__ = [
    "RemediationAction",
    "plan_remediations",
    "remediation_to_payload",
    "render_remediation_markdown",
    "render_remediation_text",
]
