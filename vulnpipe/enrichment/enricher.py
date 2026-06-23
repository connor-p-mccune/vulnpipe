"""The enrichment stage: fill CVSS / EPSS fields on findings.

Given normalized findings plus the NVD and EPSS clients, this stage looks up every
distinct CVE once and copies the results onto the findings that cite them. It is
strictly *additive*: it only fills fields that are currently unknown and never
overwrites data a scanner already provided, so existing values are preserved and
genuinely missing data stays ``None`` (never guessed).

Findings are immutable, so enriched findings are produced with ``model_copy``; the
fingerprint is unaffected because none of the enriched fields feed into it. When a
finding cites several CVEs the worst case wins -- the highest CVSS score and the
highest EPSS probability among them -- so prioritization sees the real ceiling.
"""

import logging
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from vulnpipe.core.config import Config
from vulnpipe.core.logging import get_logger, log_event
from vulnpipe.core.models import Finding
from vulnpipe.enrichment._http import CacheProtocol, open_cache
from vulnpipe.enrichment.epss_client import EpssClient, EpssScore
from vulnpipe.enrichment.nvd_client import CveDetail, NvdClient

_log = get_logger(__name__)


@dataclass(frozen=True)
class EnrichmentClients:
    """The enrichment clients; either is ``None`` when that source is disabled."""

    nvd: NvdClient | None = None
    epss: EpssClient | None = None

    def close(self) -> None:
        """Close whichever underlying clients exist."""
        if self.nvd is not None:
            self.nvd.close()
        if self.epss is not None:
            self.epss.close()


def build_enrichment(
    config: Config,
    *,
    cache: CacheProtocol | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> EnrichmentClients:
    """Construct the enrichment clients from config, sharing one on-disk cache.

    Honors the ``enrichment`` enable flags; a disabled source yields ``None`` for
    that client. The cache directory is opened only when at least one source is
    enabled (and unless a cache is injected, e.g. in tests).
    """
    shared = cache
    if shared is None and (config.enrichment.nvd_enabled or config.enrichment.epss_enabled):
        shared = open_cache(config.enrichment.cache_dir)
    return EnrichmentClients(
        nvd=NvdClient.from_config(config, cache=shared, sleep=sleep),
        epss=EpssClient.from_config(config, cache=shared, sleep=sleep),
    )


def enrich_findings(
    findings: Iterable[Finding],
    *,
    nvd: NvdClient | None = None,
    epss: EpssClient | None = None,
) -> list[Finding]:
    """Return ``findings`` with CVSS/EPSS fields filled from NVD and EPSS lookups.

    Each distinct CVE is looked up once. Findings without CVEs (or for which no
    data is found) pass through unchanged. Existing values are never overwritten
    and nothing is fabricated: a failed lookup simply leaves the field unknown.
    """
    items = list(findings)
    if not items:
        return items
    cve_ids = sorted({cve for finding in items for cve in finding.cve_ids})
    if not cve_ids:
        return items
    nvd_details = _lookup_nvd(nvd, cve_ids)
    epss_scores = epss.get_scores(cve_ids) if epss is not None else {}
    if not nvd_details and not epss_scores:
        return items
    enriched = [_enrich_finding(finding, nvd_details, epss_scores) for finding in items]
    log_event(
        _log,
        logging.INFO,
        "enrichment complete",
        findings=len(enriched),
        cves=len(cve_ids),
        nvd_hits=len(nvd_details),
        epss_hits=len(epss_scores),
    )
    return enriched


def _lookup_nvd(nvd: NvdClient | None, cve_ids: Sequence[str]) -> dict[str, CveDetail]:
    if nvd is None:
        return {}
    details: dict[str, CveDetail] = {}
    for cve in cve_ids:
        detail = nvd.get_cve(cve)
        if detail is not None:
            details[cve] = detail
    return details


def _cvss_rank(detail: CveDetail) -> tuple[float, str]:
    """Sort key selecting the highest-scoring detail (ties broken by CVE id)."""
    return (detail.cvss_score if detail.cvss_score is not None else -1.0, detail.cve_id)


def _epss_rank(score: EpssScore) -> tuple[float, str]:
    """Sort key selecting the highest EPSS probability (ties broken by CVE id)."""
    return (score.epss, score.cve_id)


def _best_cve_detail(cve_ids: Sequence[str], details: dict[str, CveDetail]) -> CveDetail | None:
    candidates = [details[cve] for cve in cve_ids if cve in details]
    return max(candidates, key=_cvss_rank) if candidates else None


def _best_epss(cve_ids: Sequence[str], scores: dict[str, EpssScore]) -> EpssScore | None:
    candidates = [scores[cve] for cve in cve_ids if cve in scores]
    return max(candidates, key=_epss_rank) if candidates else None


def _enrich_finding(
    finding: Finding,
    nvd_details: dict[str, CveDetail],
    epss_scores: dict[str, EpssScore],
) -> Finding:
    if not finding.cve_ids:
        return finding
    updates: dict[str, object] = {}
    detail = _best_cve_detail(finding.cve_ids, nvd_details)
    if detail is not None:
        if finding.cvss_score is None and detail.cvss_score is not None:
            updates["cvss_score"] = detail.cvss_score
        if finding.cvss_vector is None and detail.cvss_vector is not None:
            updates["cvss_vector"] = detail.cvss_vector
    score = _best_epss(finding.cve_ids, epss_scores)
    if score is not None:
        if finding.epss_score is None:
            updates["epss_score"] = score.epss
        if finding.epss_percentile is None and score.percentile is not None:
            updates["epss_percentile"] = score.percentile
    if not updates:
        return finding
    return finding.model_copy(update=updates)


__all__ = [
    "EnrichmentClients",
    "build_enrichment",
    "enrich_findings",
]
