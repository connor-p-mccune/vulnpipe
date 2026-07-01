"""Finding enrichment: CVSS scoring and NVD / EPSS / CISA KEV lookups.

The :func:`enrich_findings` step fills ``cvss_score`` / ``cvss_vector`` /
``epss_score`` on findings from real NVD and EPSS lookups and flags findings whose
CVE is in the CISA Known Exploited Vulnerabilities catalog (``kev``), leaving fields
unknown when a lookup fails (never guessed). Clients cache responses on disk and
back off on transient failures; build them from config with :func:`build_enrichment`.
"""

from vulnpipe.enrichment.cvss import CvssResult, parse_vector
from vulnpipe.enrichment.enricher import (
    EnrichmentClients,
    build_enrichment,
    enrich_findings,
)
from vulnpipe.enrichment.epss_client import EpssClient, EpssScore, parse_epss_response
from vulnpipe.enrichment.kev_client import KevClient, KevEntry, parse_kev_catalog
from vulnpipe.enrichment.nvd_client import CveDetail, NvdClient, parse_nvd_response

__all__ = [
    "CveDetail",
    "CvssResult",
    "EnrichmentClients",
    "EpssClient",
    "EpssScore",
    "KevClient",
    "KevEntry",
    "NvdClient",
    "build_enrichment",
    "enrich_findings",
    "parse_epss_response",
    "parse_kev_catalog",
    "parse_nvd_response",
    "parse_vector",
]
