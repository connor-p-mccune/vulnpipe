"""Ownership annotation: stamp operator-declared owner/tags onto findings.

Attaches the *owner* (the team or queue that owns an asset) and its *tags* -- both
declared by the operator in the prioritization config -- onto each finding for that
host, so triage can route a finding to whoever owns it instead of landing in a shared
pile. Ownership makes a report *actionable by team*, the difference between "here are
500 findings" and "here are your team's 12."

This is operator-supplied **context, not detection data**: it is written into
``Finding.metadata`` (which the fingerprint ignores), so annotating never changes a
finding's identity, its baseline/diff classification, or any scanner-derived field --
and it is echoed from config, never fabricated.

Pure, like the rest of ``processing/``: it takes the resolver callables rather than a
config object (staying decoupled from config loading, exactly as the prioritizer
takes its criticality resolver) and returns new findings via ``model_copy``.
"""

from collections.abc import Callable, Iterable, Sequence

from vulnpipe.core.models import Finding

#: Metadata keys the annotation writes. Plain, stable keys so they serialize cleanly
#: into the findings JSON and the reporters can read them back.
OWNER_KEY = "owner"
TAGS_KEY = "tags"

#: Resolver signatures: host -> owning team/queue, and host -> its tags.
OwnerResolver = Callable[[str], str | None]
TagsResolver = Callable[[str], Sequence[str]]


def finding_owner(finding: Finding) -> str | None:
    """The team/queue that owns a finding's asset, or ``None`` if unassigned.

    Read from the operator-declared ``owner`` metadata this module stamps on (never a
    scanner-derived field); a blank value counts as unassigned. Lives here, beside the
    annotation, so reporting and the query layer share one definition of "owner".
    """
    value = finding.metadata.get(OWNER_KEY)
    return value if isinstance(value, str) and value.strip() else None


def finding_tags(finding: Finding) -> tuple[str, ...]:
    """The operator-declared tags on a finding's asset, in declared order."""
    value = finding.metadata.get(TAGS_KEY)
    if isinstance(value, list | tuple):
        return tuple(item for item in value if isinstance(item, str) and item.strip())
    return ()


def _no_owner(host: str) -> None:
    return None


def _no_tags(host: str) -> tuple[str, ...]:
    return ()


def annotate_ownership(
    findings: Iterable[Finding],
    *,
    owner_for: OwnerResolver = _no_owner,
    tags_for: TagsResolver = _no_tags,
) -> list[Finding]:
    """Return ``findings`` with each host's owner/tags stamped into ``metadata``.

    A finding whose host resolves to neither an owner nor any tags passes through
    unchanged (by identity), so reports stay clean when ownership is not configured.
    Existing metadata is preserved; only the ``owner`` / ``tags`` keys are set.
    """
    result: list[Finding] = []
    for finding in findings:
        owner = owner_for(finding.host)
        tags = tuple(tags_for(finding.host))
        if owner is None and not tags:
            result.append(finding)
            continue
        metadata = dict(finding.metadata)
        if owner is not None:
            metadata[OWNER_KEY] = owner
        if tags:
            metadata[TAGS_KEY] = list(tags)
        result.append(finding.model_copy(update={"metadata": metadata}))
    return result


__all__ = [
    "OWNER_KEY",
    "TAGS_KEY",
    "annotate_ownership",
    "finding_owner",
    "finding_tags",
]
