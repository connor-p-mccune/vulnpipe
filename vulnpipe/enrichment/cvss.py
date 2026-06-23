"""CVSS vector parsing and scoring.

Parses CVSS vector strings into a base score and a canonical vector using the
``cvss`` library, supporting CVSS v2, v3.0/v3.1, and v4.0. The result feeds the
enrichment step, which fills ``Finding.cvss_score`` / ``Finding.cvss_vector``.

Honest by construction: a vector the library cannot parse (or whose score falls
outside ``[0, 10]``) yields ``None`` rather than a fabricated value, and the
returned score is re-derived from the vector itself so it stays internally
consistent with the canonical vector string.
"""

import logging
from dataclasses import dataclass
from typing import Any

from cvss import CVSS2, CVSS3, CVSS4, CVSSError

from vulnpipe.core.logging import get_logger, log_event
from vulnpipe.core.models import Severity

_log = get_logger(__name__)

# Maps a vector prefix to the parser class and the version label it implies. A
# CVSS v2 vector carries no prefix, so it is the fallback when none of these match.
# The parser slot is ``Any`` because the ``cvss`` classes ship no type stubs.
_PREFIXES: tuple[tuple[str, Any, str], ...] = (
    ("CVSS:4.0", CVSS4, "4.0"),
    ("CVSS:3.1", CVSS3, "3.1"),
    ("CVSS:3.0", CVSS3, "3.0"),
)


@dataclass(frozen=True)
class CvssResult:
    """A parsed CVSS vector: its base score, canonical vector, and version."""

    score: float
    vector: str
    version: str
    severity: Severity


def _coerce_score(value: Any) -> float | None:
    """Coerce a library score (a ``Decimal``) to a float in ``[0, 10]``, else ``None``."""
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if score != score:  # NaN
        return None
    if not 0.0 <= score <= 10.0:
        return None
    return score


def _classify(text: str) -> tuple[Any, str] | None:
    """Pick the parser class + version label for ``text`` by its CVSS prefix.

    A recognized ``CVSS:<v>`` prefix selects the matching class; a bare vector
    (no prefix) is treated as CVSS v2. An unrecognized ``CVSS:`` version returns
    ``None`` -- it is reported as unknown rather than parsed under the wrong rules.
    """
    upper = text.upper()
    for prefix, parser, version in _PREFIXES:
        if upper.startswith(prefix):
            return parser, version
    if upper.startswith("CVSS:"):
        return None
    return CVSS2, "2.0"


def parse_vector(vector: str | None) -> CvssResult | None:
    """Parse a CVSS vector string into a :class:`CvssResult`, or ``None``.

    Detects the CVSS version from the vector prefix and parses it with the
    matching ``cvss`` class. The base score is taken from the vector math, so it
    is internally consistent with the returned canonical vector. Unparseable,
    unsupported, or out-of-range input returns ``None`` -- never a guessed score.
    """
    if vector is None:
        return None
    text = vector.strip()
    if not text:
        return None
    classified = _classify(text)
    if classified is None:
        log_event(_log, logging.DEBUG, "cvss vector unsupported version", vector=text)
        return None
    parser, version = classified
    try:
        metric = parser(text)
    except CVSSError as exc:
        log_event(_log, logging.DEBUG, "cvss vector parse failed", vector=text, error=str(exc))
        return None
    score = _coerce_score(metric.base_score)
    if score is None:
        return None
    return CvssResult(
        score=score,
        vector=str(metric.clean_vector()),
        version=version,
        severity=Severity.from_cvss_score(score),
    )


__all__ = ["CvssResult", "parse_vector"]
