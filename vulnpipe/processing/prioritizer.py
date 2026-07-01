"""Order findings so the most actionable issues surface first.

Reporting consumes findings in priority order. The ranking is deterministic and
layered, each key breaking ties left by the previous one:

1. **severity** -- the normalized cross-scanner bucket (CVSS-derived for scored
   findings, ZAP-risk-derived otherwise), so a High always outranks a Medium even
   when one side has no CVSS score;
2. **known-exploited (KEV)** -- among equally severe findings, those whose CVE is in
   the CISA KEV catalog (actively exploited in the wild) surface first;
3. **CVSS base score** -- finer ordering within a severity band;
4. **EPSS probability** -- how likely the issue is to be exploited;
5. **asset criticality** -- how important the affected host is (from config);
6. **fingerprint** -- a stable final tie-breaker so the order is fully reproducible.

Missing CVSS/EPSS values sort last within their tier: an unknown score is never
treated as a high one. Pure function -- findings in, a new ordered list out, with
the input left untouched. Asset criticality is supplied by the caller (resolved
from configuration via :meth:`~vulnpipe.core.config.PrioritizationConfig.criticality_for`)
so this module stays decoupled from config loading.
"""

from collections.abc import Callable, Iterable

from vulnpipe.core.models import AssetCriticality, Finding

CriticalityResolver = Callable[[str], AssetCriticality]

_MISSING_SCORE = -1.0  # sorts below any real CVSS (0..10) or EPSS (0..1) value


def prioritize(
    findings: Iterable[Finding],
    *,
    criticality: CriticalityResolver | None = None,
) -> list[Finding]:
    """Return ``findings`` ordered most-actionable first (see the module docstring).

    ``criticality`` maps a host to its :class:`AssetCriticality`; when omitted every
    asset is treated as :attr:`AssetCriticality.MEDIUM`, so criticality has no effect
    and ordering falls to severity, CVSS, EPSS, then fingerprint.
    """
    resolve = criticality if criticality is not None else _uniform_criticality
    return sorted(findings, key=lambda finding: _sort_key(finding, resolve))


def _uniform_criticality(_host: str) -> AssetCriticality:
    return AssetCriticality.MEDIUM


def _sort_key(
    finding: Finding, resolve: CriticalityResolver
) -> tuple[int, int, float, float, int, str]:
    """Ascending sort key encoding the descending priority order.

    Ranks, flags, and scores are negated so a plain ascending sort puts the highest
    first; the fingerprint stays ascending as the stable final tie-breaker.
    """
    cvss = finding.cvss_score if finding.cvss_score is not None else _MISSING_SCORE
    epss = finding.epss_score if finding.epss_score is not None else _MISSING_SCORE
    return (
        -finding.severity.rank,
        -int(finding.kev),
        -cvss,
        -epss,
        -resolve(finding.host).rank,
        finding.fingerprint,
    )


__all__ = ["CriticalityResolver", "prioritize"]
