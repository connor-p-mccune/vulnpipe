"""Explain a single finding: the full story behind why it ranks where it does.

A report shows *what* was found and a prioritized order; ``vulnpipe explain`` opens
up one finding and shows *why*. It is the transparency capstone for everything the
pipeline computes: the composite risk score is broken down into its exact inputs and
formula (no black box), alongside the CVSS/EPSS/KEV enrichment, the OWASP / CWE Top 25
standards mapping, the asset owner, and the remediation -- all for one finding a user
picks by fingerprint, position, or title.

Pure and deterministic: :func:`select_finding` chooses a finding, :func:`explain_payload`
serializes the breakdown, and :func:`render_explain` renders a fixed-width text view.
The risk breakdown comes straight from :func:`~vulnpipe.core.models.risk_components`,
the single source of the score, so the explanation can never disagree with the number.
"""

import io
from collections.abc import Iterable
from typing import Any

from rich.console import Console
from rich.table import Table

from vulnpipe.core.models import Finding, risk_components
from vulnpipe.core.standards import cwe_top_25, owasp_categories
from vulnpipe.reporting.summary import finding_owner, finding_tags

#: Fixed render width so the text output is stable regardless of the real terminal.
_WIDTH = 100

#: Human-readable phrasing for each risk axis source.
_IMPACT_SOURCE = {
    "cvss": "CVSS base score / 10",
    "severity": "severity band (no CVSS score available)",
}
_LIKELIHOOD_SOURCE = {
    "kev": "known-exploited (CISA KEV) -> 1.0",
    "epss": "EPSS exploit probability",
    "none": "no KEV/EPSS signal -> 0.0 floor",
}


class ExplainError(Exception):
    """Raised when a finding cannot be uniquely selected to explain."""


def select_finding(
    findings: Iterable[Finding],
    *,
    fingerprint: str | None = None,
    index: int | None = None,
    title: str | None = None,
) -> Finding:
    """Select exactly one finding by fingerprint, 1-based index, or title substring.

    Exactly one selector must be given. A ``fingerprint`` matches the full digest or a
    unique prefix (>= 7 chars, git-style); ``title`` is a case-insensitive substring.
    Raises :class:`ExplainError` when zero or more than one finding matches (with a
    message that says which), so the caller can surface a clear error.
    """
    provided = [
        name
        for name, value in (("fingerprint", fingerprint), ("index", index), ("title", title))
        if value is not None
    ]
    if len(provided) != 1:
        raise ExplainError("provide exactly one of --fingerprint / --index / --title")
    items = list(findings)

    if fingerprint is not None:
        fp = fingerprint.strip().lower()
        exact = [f for f in items if f.fingerprint == fp]
        if exact:
            return exact[0]
        if len(fp) < 7:
            raise ExplainError(f"no finding with fingerprint {fingerprint!r}")
        prefix = [f for f in items if f.fingerprint.startswith(fp)]
        if len(prefix) == 1:
            return prefix[0]
        if not prefix:
            raise ExplainError(f"no finding with fingerprint {fingerprint!r}")
        raise ExplainError(f"fingerprint prefix {fingerprint!r} is ambiguous ({len(prefix)} match)")

    if index is not None:
        if index < 1 or index > len(items):
            raise ExplainError(f"index {index} out of range (1..{len(items)})")
        return items[index - 1]

    query = (title or "").strip().lower()
    matches = [f for f in items if query in f.title.lower()]
    if not matches:
        raise ExplainError(f"no finding matching title {title!r}")
    if len(matches) > 1:
        raise ExplainError(
            f"title {title!r} matches {len(matches)} findings; narrow it or use --fingerprint"
        )
    return matches[0]


def explain_payload(finding: Finding) -> dict[str, Any]:
    """Serialize the full, deterministic breakdown of one finding into a mapping."""
    components = risk_components(
        severity=finding.severity,
        cvss_score=finding.cvss_score,
        epss_score=finding.epss_score,
        kev=finding.kev,
    )
    return {
        "fingerprint": finding.fingerprint,
        "title": finding.title,
        "host": finding.host,
        "port": finding.port,
        "source": finding.source,
        "plugin_id": finding.plugin_id,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value if finding.confidence is not None else None,
        "risk": {
            "score": components.score,
            "impact": round(components.impact, 4),
            "impact_source": components.impact_source,
            "likelihood": round(components.likelihood, 4),
            "likelihood_source": components.likelihood_source,
            "base_weight": components.base_weight,
        },
        "cvss": {"score": finding.cvss_score, "vector": finding.cvss_vector},
        "epss": {"score": finding.epss_score, "percentile": finding.epss_percentile},
        "kev": finding.kev,
        "cve_ids": list(finding.cve_ids),
        "cwe_ids": list(finding.cwe_ids),
        "owasp": [
            {"short": category.short, "title": category.title}
            for category in owasp_categories(finding.cwe_ids)
        ],
        "cwe_top_25": bool(cwe_top_25(finding.cwe_ids)),
        "owner": finding_owner(finding),
        "tags": list(finding_tags(finding)),
        "solution": finding.solution,
        "references": list(finding.references),
    }


def _host_label(finding: Finding) -> str:
    return finding.host if finding.port is None else f"{finding.host}:{finding.port}"


def _identity_table(finding: Finding) -> Table:
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column("field", style="bold")
    table.add_column("value")
    table.add_row("Severity", finding.severity.value)
    if finding.confidence is not None:
        table.add_row("Confidence", finding.confidence.value)
    table.add_row("Source", finding.source)
    if finding.plugin_id:
        table.add_row("Plugin/alert", finding.plugin_id)
    table.add_row("Fingerprint", finding.fingerprint)
    return table


def _percent(value: float | None) -> str:
    return f"{value * 100:.1f}%" if value is not None else "unknown"


def render_explain(finding: Finding) -> str:
    """Render a deterministic, fixed-width explanation of one finding."""
    components = risk_components(
        severity=finding.severity,
        cvss_score=finding.cvss_score,
        epss_score=finding.epss_score,
        kev=finding.kev,
    )
    base = components.base_weight
    buffer = io.StringIO()
    console = Console(file=buffer, width=_WIDTH, force_terminal=False, highlight=False)

    console.print(f"{finding.title}  [dim]on[/] {_host_label(finding)}")
    console.print(_identity_table(finding))

    console.print(f"\nRisk score: {components.score}/100")
    console.print(
        f"  impact      = {components.impact:.2f}  ({_IMPACT_SOURCE[components.impact_source]})"
    )
    console.print(
        f"  likelihood  = {components.likelihood:.2f}  "
        f"({_LIKELIHOOD_SOURCE[components.likelihood_source]})"
    )
    console.print(
        f"  score       = round(impact x ({base:g} + {1 - base:g} x likelihood) x 100) "
        f"= {components.score}"
    )

    console.print("\nEnrichment")
    cvss = f"{finding.cvss_score:.1f}" if finding.cvss_score is not None else "unknown"
    console.print(f"  CVSS   {cvss}" + (f"  {finding.cvss_vector}" if finding.cvss_vector else ""))
    console.print(
        f"  EPSS   {_percent(finding.epss_score)}"
        + (f" (percentile {_percent(finding.epss_percentile)})" if finding.epss_percentile else "")
    )
    console.print(f"  KEV    {'yes - actively exploited in the wild' if finding.kev else 'no'}")

    console.print("\nClassification")
    console.print(f"  CVEs   {', '.join(finding.cve_ids) if finding.cve_ids else '—'}")
    console.print(f"  CWEs   {', '.join(finding.cwe_ids) if finding.cwe_ids else '—'}")
    owasp = owasp_categories(finding.cwe_ids)
    console.print(
        "  OWASP  " + (", ".join(f"{c.short} {c.title}" for c in owasp) if owasp else "—")
    )
    if cwe_top_25(finding.cwe_ids):
        console.print("  CWE Top 25  yes (a 2023 Most Dangerous Weakness)")

    owner = finding_owner(finding)
    tags = finding_tags(finding)
    if owner is not None or tags:
        console.print("\nOwnership")
        console.print(f"  Owner  {owner if owner is not None else 'unassigned'}")
        if tags:
            console.print(f"  Tags   {', '.join(tags)}")

    if finding.solution or finding.references:
        console.print("\nRemediation")
        if finding.solution:
            console.print(f"  {finding.solution}")
        for reference in finding.references[:5]:
            console.print(f"  - {reference}")
    return buffer.getvalue()


__all__ = [
    "ExplainError",
    "explain_payload",
    "render_explain",
    "select_finding",
]
