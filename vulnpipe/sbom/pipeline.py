"""Standalone SBOM analysis pipeline: an SBOM file in, prioritized findings out.

Ties the SBOM layer's stages together for the ``vulnpipe sbom`` command and for
reuse elsewhere: load the CycloneDX document, query OSV for each component, enrich
the resulting findings with EPSS probabilities and CISA KEV status (both keyless
sources, so no configuration is required), then deduplicate and prioritize -- the
same processing the main pipeline applies to scanner output.

Unlike the network/web scanners this is passive: it reads a local file and queries
public advisory APIs, touching none of the described software. The clients are
injectable so the whole flow is unit-testable without network access, and each
distinct component/advisory maps to one stable finding, so output is deterministic
for a fixed SBOM and advisory state.
"""

from pathlib import Path

from vulnpipe.core.models import Finding
from vulnpipe.enrichment._http import CacheProtocol, open_cache
from vulnpipe.enrichment.enricher import enrich_findings
from vulnpipe.enrichment.epss_client import EpssClient
from vulnpipe.enrichment.kev_client import KevClient
from vulnpipe.processing.deduplicator import deduplicate
from vulnpipe.processing.prioritizer import prioritize
from vulnpipe.sbom.analyzer import analyze_sbom
from vulnpipe.sbom.cyclonedx import load_sbom
from vulnpipe.sbom.osv_client import OsvClient

#: Default on-disk cache directory (shared with the enrichment clients).
DEFAULT_CACHE_DIR = ".cache"


def _enrich(findings: list[Finding], cache: CacheProtocol | None) -> list[Finding]:
    """Enrich SBOM findings with EPSS + KEV (keyless sources), then close the clients."""
    if not findings:
        return findings
    epss = EpssClient(cache=cache)
    kev = KevClient(cache=cache)
    try:
        return enrich_findings(findings, epss=epss, kev=kev)
    finally:
        epss.close()
        kev.close()


def run_sbom_pipeline(
    sbom_path: str | Path,
    *,
    enrich: bool = True,
    cache_dir: str | Path = DEFAULT_CACHE_DIR,
    osv: OsvClient | None = None,
    cache: CacheProtocol | None = None,
) -> list[Finding]:
    """Analyze a CycloneDX SBOM into prioritized findings.

    Loads ``sbom_path``, queries OSV per component, optionally enriches with EPSS +
    KEV, then deduplicates and prioritizes. ``osv`` / ``cache`` are injectable for
    testing; by default a shared on-disk cache under ``cache_dir`` backs both the
    OSV client and enrichment. Raises
    :class:`~vulnpipe.sbom.cyclonedx.SbomError` if the SBOM cannot be read.
    """
    sbom = load_sbom(sbom_path)
    shared = cache if cache is not None else open_cache(cache_dir)
    client = osv if osv is not None else OsvClient(cache=shared)
    try:
        findings = analyze_sbom(sbom, client)
    finally:
        if osv is None:
            client.close()
    if enrich:
        findings = _enrich(findings, shared)
    return prioritize(deduplicate(findings))


__all__ = ["DEFAULT_CACHE_DIR", "run_sbom_pipeline"]
