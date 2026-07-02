"""Shared, pure view-model helpers for the reporters.

The JSON and HTML reporters both need the same derived numbers -- how many
findings there are, how they break down by severity, and how they group per host.
Keeping that logic here (pure ``findings in -> values out``) means the reporters
stay thin and the counts are computed one way, so the JSON summary and the HTML
summary can never drift apart.

Everything here is deterministic for fixed input: severities are reported in a
fixed worst-to-least order and host groups are ordered by their worst finding,
then host name, so report output is stable across runs.
"""

from collections.abc import Iterable
from dataclasses import dataclass

from vulnpipe.core.models import Finding, Severity
from vulnpipe.core.standards import (
    OWASP_TOP_10_2021,
    OwaspCategory,
    cwe_top_25,
    owasp_categories,
)

#: Severities in display order: most severe first. Reporters iterate this so the
#: summary always lists every band (including zero counts) in a stable order.
SEVERITY_DISPLAY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFORMATIONAL,
)


def severity_counts(findings: Iterable[Finding]) -> dict[Severity, int]:
    """Count findings per severity, with every band present in display order.

    Bands with no findings are included with a count of ``0`` so callers can render
    a complete, fixed-shape breakdown without special-casing missing severities.
    """
    counts = dict.fromkeys(SEVERITY_DISPLAY_ORDER, 0)
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def count_hosts(findings: Iterable[Finding]) -> int:
    """Return the number of distinct hosts represented in ``findings``."""
    return len({finding.host for finding in findings})


@dataclass(frozen=True)
class ReportSummary:
    """Top-level totals shared by every report format."""

    total: int
    host_count: int
    by_severity: dict[Severity, int]


def summarize(findings: Iterable[Finding]) -> ReportSummary:
    """Compute the :class:`ReportSummary` for ``findings`` (a single pass per metric)."""
    items = list(findings)
    return ReportSummary(
        total=len(items),
        host_count=count_hosts(items),
        by_severity=severity_counts(items),
    )


def finding_owasp(finding: Finding) -> tuple[OwaspCategory, ...]:
    """The OWASP Top 10 categories ``finding``'s CWE references map to, in rank order.

    Empty when the finding has no CWE references or none of them are in the curated
    OWASP mapping -- an unmapped finding is reported as such, never forced into a
    category.
    """
    return owasp_categories(finding.cwe_ids)


@dataclass(frozen=True)
class StandardsSummary:
    """How findings distribute over the OWASP Top 10 2021 and the 2023 CWE Top 25.

    ``owasp`` holds every category in rank order (zeros included) so reporters can
    render a fixed-shape breakdown. A finding citing CWEs from several categories is
    counted in each of them; ``uncategorized`` counts findings that map to none.
    """

    owasp: dict[OwaspCategory, int]
    uncategorized: int
    cwe_top_25: int

    @property
    def any_mapped(self) -> bool:
        """Whether at least one finding maps to an OWASP Top 10 category."""
        return any(self.owasp.values())


def summarize_standards(findings: Iterable[Finding]) -> StandardsSummary:
    """Compute the :class:`StandardsSummary` for ``findings`` (pure and deterministic)."""
    counts: dict[OwaspCategory, int] = dict.fromkeys(OWASP_TOP_10_2021, 0)
    uncategorized = 0
    top_25 = 0
    for finding in findings:
        categories = owasp_categories(finding.cwe_ids)
        if categories:
            for category in categories:
                counts[category] += 1
        else:
            uncategorized += 1
        if cwe_top_25(finding.cwe_ids):
            top_25 += 1
    return StandardsSummary(owasp=counts, uncategorized=uncategorized, cwe_top_25=top_25)


@dataclass(frozen=True)
class HostGroup:
    """The findings for one host, with its per-severity counts and worst severity."""

    host: str
    findings: tuple[Finding, ...]
    counts: dict[Severity, int]
    highest: Severity


def group_by_host(findings: Iterable[Finding]) -> list[HostGroup]:
    """Group findings by host, worst-affected host first.

    Findings keep their incoming (prioritized) order within each group; the groups
    themselves are ordered by their highest severity, then host name, so the
    per-host breakdown is deterministic regardless of how the hosts interleave in
    the input.
    """
    buckets: dict[str, list[Finding]] = {}
    for finding in findings:
        buckets.setdefault(finding.host, []).append(finding)

    groups = [
        HostGroup(
            host=host,
            findings=tuple(items),
            counts=severity_counts(items),
            highest=max((finding.severity for finding in items), key=lambda s: s.rank),
        )
        for host, items in buckets.items()
    ]
    groups.sort(key=lambda group: (-group.highest.rank, group.host))
    return groups


__all__ = [
    "SEVERITY_DISPLAY_ORDER",
    "HostGroup",
    "ReportSummary",
    "StandardsSummary",
    "count_hosts",
    "finding_owasp",
    "group_by_host",
    "severity_counts",
    "summarize",
    "summarize_standards",
]
