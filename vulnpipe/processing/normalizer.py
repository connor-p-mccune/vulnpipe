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


__all__ = [
    "clean_cves",
    "clean_text",
    "clean_tuple",
    "normalize_cve",
    "parse_cvss",
]
