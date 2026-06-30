"""Normalization helpers shared by the scanners.

Both scanners build :class:`~vulnpipe.core.models.Finding` objects through these
helpers so fingerprints and field conventions stay consistent regardless of the
source tool. This module holds the small, pure string/number cleaners used while
mapping raw scanner output onto the model: whitespace trimming, deterministic
de-duplication of reference/CVE/CWE lists, CVE-id validation, and CVSS parsing.

Keeping these honest matters for the project's hard rules: a CVE that does not
match the canonical pattern is dropped rather than guessed, and a CVSS score that
is missing or out of range becomes ``None`` (unknown) instead of a fabricated
value.
"""

import re
from collections.abc import Iterable
from typing import Any

from vulnpipe.core.models import Confidence, Finding, Severity

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def clean_text(value: str | None) -> str | None:
    """Strip surrounding whitespace; return ``None`` for empty/whitespace-only input.

    Internal whitespace is preserved so multi-line descriptions keep their shape.
    """
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def clean_tuple(values: Iterable[str | None]) -> tuple[str, ...]:
    """Strip entries, drop empties, and de-duplicate preserving first-seen order.

    Determinism here keeps report output and fingerprints stable across runs.
    """
    seen: dict[str, None] = {}
    for value in values:
        if value is None:
            continue
        stripped = value.strip()
        if stripped and stripped not in seen:
            seen[stripped] = None
    return tuple(seen)


def normalize_cve(value: str | None) -> str | None:
    """Return the canonical upper-case CVE id, or ``None`` if ``value`` is not a CVE.

    Accepts any case and surrounding whitespace; rejects anything that is not a
    full ``CVE-YYYY-NNNN`` identifier so malformed scanner output is never coerced
    into a fake CVE id.
    """
    if value is None:
        return None
    match = _CVE_RE.fullmatch(value.strip())
    return match.group(0).upper() if match else None


def clean_cves(values: Iterable[str | None]) -> tuple[str, ...]:
    """Normalize, validate, and de-duplicate a collection of CVE ids."""
    seen: dict[str, None] = {}
    for value in values:
        cve = normalize_cve(value)
        if cve is not None and cve not in seen:
            seen[cve] = None
    return tuple(seen)


def parse_cvss(value: float | int | str | None) -> float | None:
    """Parse a CVSS base score, returning ``None`` when missing or out of range.

    CVSS v3 scores live in ``[0.0, 10.0]``; anything unparseable, NaN, or outside
    that range is treated as unknown rather than clamped to a fabricated value.
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if score != score:  # NaN
        return None
    if not 0.0 <= score <= 10.0:
        return None
    return score


def make_finding(
    *,
    source: str,
    host: str,
    title: str,
    severity: Severity | None = None,
    port: int | None = None,
    protocol: str | None = None,
    plugin_id: str | None = None,
    confidence: Confidence | None = None,
    description: str | None = None,
    solution: str | None = None,
    evidence: str | None = None,
    references: Iterable[str | None] = (),
    cve_ids: Iterable[str | None] = (),
    cwe_ids: Iterable[str | None] = (),
    cvss_score: float | int | str | None = None,
    cvss_vector: str | None = None,
    epss_score: float | None = None,
    epss_percentile: float | None = None,
    kev: bool = False,
    metadata: dict[str, Any] | None = None,
) -> Finding:
    """Assemble a cleaned, frozen :class:`Finding` -- the one construction path.

    Every scanner routes through here so field conventions stay uniform: text is
    trimmed, list fields are de-duplicated, CVE ids are validated, and the CVSS
    score is parsed. When ``severity`` is not given it is derived from the parsed
    CVSS score (falling back to ``INFORMATIONAL`` when no score is available), so
    a severity is never invented out of thin air.
    """
    display_title = " ".join(title.split())
    if not display_title:
        raise ValueError("Finding title must be non-empty")
    score = parse_cvss(cvss_score)
    if severity is None:
        severity = Severity.from_cvss_score(score) if score is not None else Severity.INFORMATIONAL
    return Finding(
        source=source,
        host=host,
        title=display_title,
        severity=severity,
        port=port,
        protocol=protocol,
        plugin_id=clean_text(plugin_id),
        confidence=confidence,
        description=clean_text(description),
        solution=clean_text(solution),
        evidence=clean_text(evidence),
        references=clean_tuple(references),
        cve_ids=clean_cves(cve_ids),
        cwe_ids=clean_tuple(cwe_ids),
        cvss_score=score,
        cvss_vector=clean_text(cvss_vector),
        epss_score=epss_score,
        epss_percentile=epss_percentile,
        kev=kev,
        metadata=metadata if metadata is not None else {},
    )


__all__ = [
    "clean_cves",
    "clean_text",
    "clean_tuple",
    "make_finding",
    "normalize_cve",
    "parse_cvss",
]
