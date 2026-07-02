"""SBOM analysis: turn OSV advisories for declared components into findings.

Bridges the SBOM layer onto the pipeline's one shared model: each advisory OSV
reports for a declared component becomes a normalized
:class:`~vulnpipe.core.models.Finding` (via the same
:func:`~vulnpipe.processing.normalizer.make_finding` path the scanners use), so
supply-chain findings flow through the existing reporting, diffing, and gating
machinery unchanged.

Mapping choices, in the project's honest-by-construction style:

* ``host`` is the SBOM's *subject* (the application the SBOM describes) -- the
  stable identity the CI baseline keys on; the affected package and version live
  in the title and metadata.
* ``plugin_id`` is the OSV id, so the fingerprint distinguishes advisories.
* severity comes from the advisory's own CVSS vector when it carries one
  (score re-derived from the vector math); with no vector the severity stays
  ``informational`` -- unknown is never upgraded to a guess. EPSS/KEV enrichment
  and the composite risk score still lift truly urgent findings afterwards.
* the remediation ``solution`` is stated only when OSV declares fixed versions.

Components that cannot be queried (no purl or no version) are skipped with a
logged warning -- reported as unanalyzed, not silently treated as clean.
"""

import logging

from vulnpipe.core.logging import get_logger, log_event
from vulnpipe.core.models import Finding
from vulnpipe.enrichment.cvss import parse_vector
from vulnpipe.processing.normalizer import make_finding
from vulnpipe.sbom.cyclonedx import Component, Sbom
from vulnpipe.sbom.osv_client import OsvClient, OsvVulnerability

_log = get_logger(__name__)

#: ``Finding.source`` for SBOM-derived findings.
SOURCE = "sbom"


def _title(component: Component, vuln: OsvVulnerability) -> str:
    """Stable finding title: the advisory id plus the affected package@version."""
    return f"{vuln.id}: {component.label}"


def _solution(component: Component, vuln: OsvVulnerability) -> str | None:
    """A remediation line from OSV's declared fixed versions, or ``None``."""
    if not vuln.fixed_versions:
        return None
    versions = ", ".join(vuln.fixed_versions)
    return f"Update {component.name} to {versions} or later."


def _finding(subject: str, component: Component, vuln: OsvVulnerability) -> Finding:
    cvss = parse_vector(vuln.cvss_vector)
    metadata: dict[str, object] = {
        "package": component.name,
        "package_version": component.version,
        "osv_id": vuln.id,
    }
    if component.purl is not None:
        metadata["purl"] = component.purl
    if component.ecosystem is not None:
        metadata["ecosystem"] = component.ecosystem
    if vuln.aliases:
        metadata["aliases"] = list(vuln.aliases)
    return make_finding(
        source=SOURCE,
        host=subject,
        title=_title(component, vuln),
        plugin_id=vuln.id,
        description=vuln.summary,
        solution=_solution(component, vuln),
        references=vuln.references,
        cve_ids=vuln.aliases,  # non-CVE aliases are filtered by normalization
        cvss_score=cvss.score if cvss is not None else None,
        cvss_vector=cvss.vector if cvss is not None else None,
        metadata=metadata,
    )


def analyze_sbom(sbom: Sbom, client: OsvClient) -> list[Finding]:
    """Query OSV for every queryable component and return normalized findings.

    Components appear in SBOM order and advisories in OSV-id order (the client
    sorts them), so output is deterministic for a fixed SBOM and advisory state.
    """
    findings: list[Finding] = []
    skipped = 0
    for component in sbom.components:
        if component.purl is None or component.version is None:
            skipped += 1
            log_event(
                _log,
                logging.WARNING,
                "sbom component not queryable (needs purl and version); skipping",
                component=component.label,
            )
            continue
        for vuln in client.query(component.purl, component.version):
            findings.append(_finding(sbom.subject, component, vuln))
    log_event(
        _log,
        logging.INFO,
        "sbom analysis complete",
        subject=sbom.subject,
        components=len(sbom.components),
        skipped=skipped,
        findings=len(findings),
    )
    return findings


__all__ = ["SOURCE", "analyze_sbom"]
