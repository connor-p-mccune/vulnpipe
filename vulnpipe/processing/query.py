"""Composable findings query: select a subset by severity, risk, owner, source, ...

A report is often too big to act on whole -- a team wants *their* findings, an
on-call wants only what is actively exploited, a release gate wants the high-and-above
slice. :func:`apply_query` filters a findings list by a set of predicates and returns
ordinary findings (in their original prioritized order), so the result is still a
normal report that flows into ``report`` / ``stats`` / ``gate`` / ``notify`` unchanged.

Semantics are **AND across criteria, OR within a repeated one**: ``severity>=high AND
risk>=70 AND (owner in {team-web, team-api})`` keeps a finding only if every set
criterion holds, and a repeated criterion (several owners, sources, tags, or CVEs) is
satisfied by any one match. Pure and deterministic -- no criterion given means "keep
everything".
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from vulnpipe.core.models import Finding, Severity
from vulnpipe.processing.ownership import finding_owner, finding_tags


@dataclass(frozen=True)
class FindingQuery:
    """A set of predicates to select findings by. Any field left unset is ignored.

    ``owners`` and ``unassigned`` combine as an OR (keep a finding whose owner is one
    of ``owners`` *or*, when ``unassigned`` is set, one with no owner), so a single
    query can ask for "team-web's or nobody's findings".
    """

    min_severity: Severity | None = None
    min_risk: int | None = None
    kev_only: bool = False
    owners: tuple[str, ...] = ()
    unassigned: bool = False
    sources: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    cves: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        """Whether the query constrains nothing (so it keeps every finding)."""
        return not (
            self.min_severity is not None
            or self.min_risk is not None
            or self.kev_only
            or self.owners
            or self.unassigned
            or self.sources
            or self.hosts
            or self.tags
            or self.cves
        )


def _matches_owner(finding: Finding, query: FindingQuery) -> bool:
    if not query.owners and not query.unassigned:
        return True
    owner = finding_owner(finding)
    return (owner is not None and owner in query.owners) or (query.unassigned and owner is None)


def matches(finding: Finding, query: FindingQuery) -> bool:
    """Whether ``finding`` satisfies every criterion in ``query``."""
    if query.min_severity is not None and finding.severity.rank < query.min_severity.rank:
        return False
    if query.min_risk is not None and finding.risk_score < query.min_risk:
        return False
    if query.kev_only and not finding.kev:
        return False
    if query.sources and finding.source.lower() not in {s.lower() for s in query.sources}:
        return False
    if query.hosts and not any(host.lower() in finding.host.lower() for host in query.hosts):
        return False
    if not _matches_owner(finding, query):
        return False
    if query.tags and not (set(finding_tags(finding)) & set(query.tags)):
        return False
    if query.cves:
        wanted = {cve.upper() for cve in query.cves}
        if not wanted & {cve.upper() for cve in finding.cve_ids}:
            return False
    return True


def apply_query(findings: Iterable[Finding], query: FindingQuery) -> list[Finding]:
    """Return the findings satisfying ``query``, preserving their input order."""
    return [finding for finding in findings if matches(finding, query)]


def build_query(
    *,
    min_severity: Severity | None = None,
    min_risk: int | None = None,
    kev_only: bool = False,
    owners: Sequence[str] | None = None,
    unassigned: bool = False,
    sources: Sequence[str] | None = None,
    hosts: Sequence[str] | None = None,
    tags: Sequence[str] | None = None,
    cves: Sequence[str] | None = None,
) -> FindingQuery:
    """Build a :class:`FindingQuery`, normalizing optional sequences to tuples.

    A small convenience so a CLI can pass ``None`` for "not given" and get an empty
    tuple (the "ignore this criterion" value) without repeating the coercion.
    """
    return FindingQuery(
        min_severity=min_severity,
        min_risk=min_risk,
        kev_only=kev_only,
        owners=tuple(owners or ()),
        unassigned=unassigned,
        sources=tuple(sources or ()),
        hosts=tuple(hosts or ()),
        tags=tuple(tags or ()),
        cves=tuple(cves or ()),
    )


__all__ = [
    "FindingQuery",
    "apply_query",
    "build_query",
    "matches",
]
