"""Finding enrichment: CVSS scoring and NVD / EPSS lookups.

The :func:`enrich_findings` step fills ``cvss_score`` / ``cvss_vector`` /
``epss_score`` on findings from real NVD and EPSS lookups, leaving fields unknown
when a lookup fails (never guessed). Clients cache responses on disk and back off
on transient failures; build them from config with :func:`build_enrichment`.
"""

from vulnpipe.enrichment.cvss import CvssResult, parse_vector
from vulnpipe.enrichment.enricher import (
    EnrichmentClients,
    build_enrichment,
    enrich_findings,
)
from vulnpipe.enrichment.epss_client import EpssClient, EpssScore, parse_epss_response
from vulnpipe.enrichment.nvd_client import CveDetail, NvdClient, parse_nvd_response

__all__ = [
    "CveDetail",
    "CvssResult",
    "EnrichmentClients",
    "EpssClient",
    "EpssScore",
    "NvdClient",
    "build_enrichment",
    "enrich_findings",
    "parse_epss_response",
    "parse_nvd_response",
    "parse_vector",
]
