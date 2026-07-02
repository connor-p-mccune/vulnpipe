"""Supply-chain (SBOM) analysis: known-vulnerable components via OSV.dev.

Parses a CycloneDX component inventory (:mod:`vulnpipe.sbom.cyclonedx`), queries
the OSV.dev advisory database per component (:mod:`vulnpipe.sbom.osv_client`),
and normalizes the advisories into standard pipeline findings
(:mod:`vulnpipe.sbom.analyzer`) -- so supply-chain results flow through the same
reporting, diffing, and gating machinery as scanner output.

This layer is passive: it reads a local SBOM file and queries a public advisory
API. It never probes the described software, so it sits outside the
authorization-scope gate that governs active scanning.
"""

from vulnpipe.sbom.analyzer import SOURCE, analyze_sbom
from vulnpipe.sbom.cyclonedx import Component, Sbom, SbomError, load_sbom, parse_cyclonedx
from vulnpipe.sbom.osv_client import (
    DEFAULT_OSV_URL,
    OsvClient,
    OsvVulnerability,
    parse_osv_response,
)

__all__ = [
    "DEFAULT_OSV_URL",
    "SOURCE",
    "Component",
    "OsvClient",
    "OsvVulnerability",
    "Sbom",
    "SbomError",
    "analyze_sbom",
    "load_sbom",
    "parse_cyclonedx",
    "parse_osv_response",
]
