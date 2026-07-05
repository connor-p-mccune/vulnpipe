"""Import a Trivy JSON report into normalized findings.

Parses the JSON `Trivy <https://trivy.dev>`_ emits (``trivy image -f json``,
``trivy fs``, ``trivy sbom`` …) -- a document of ``Results``, each a target with a
``Vulnerabilities`` list -- into :class:`~vulnpipe.core.models.Finding` objects via
the shared :func:`~vulnpipe.processing.normalizer.make_finding` path. Severity comes
from Trivy's own rating, the CVSS score/vector from the highest-scoring source in the
advisory's ``CVSS`` map, and the remediation line from ``FixedVersion`` -- nothing is
fabricated, and a missing field becomes ``None``.

Package identity (name / version / fixed version) is carried in metadata, so the
imported findings drop straight into the remediation planner (which groups by
package) and the rest of the pipeline. Pure and deterministic: findings are ordered
by package then vulnerability id.
"""

from typing import Any

from vulnpipe.core.models import Finding
from vulnpipe.ingest import IngestError, severity_from_label
from vulnpipe.processing.normalizer import make_finding, parse_cvss

#: ``Finding.source`` for Trivy-imported findings.
SOURCE = "trivy"


def _str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _best_cvss(cvss: Any) -> tuple[float | None, str | None]:
    """Pick the highest CVSS v3 base score (and its vector) across advisory sources."""
    if not isinstance(cvss, dict):
        return None, None
    best_score: float | None = None
    best_vector: str | None = None
    for entry in cvss.values():
        if not isinstance(entry, dict):
            continue
        score = parse_cvss(entry.get("V3Score"))
        if score is not None and (best_score is None or score > best_score):
            best_score = score
            best_vector = _str(entry.get("V3Vector"))
    return best_score, best_vector


def _references(vuln: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    primary = _str(vuln.get("PrimaryURL"))
    if primary is not None:
        refs.append(primary)
    raw = vuln.get("References")
    if isinstance(raw, list):
        refs.extend(item for item in raw if isinstance(item, str))
    return refs


def _solution(pkg: str | None, fixed: str | None) -> str | None:
    if pkg is not None and fixed is not None:
        return f"Update {pkg} to {fixed} or later."
    return None


def _purl(vuln: dict[str, Any]) -> str | None:
    identifier = vuln.get("PkgIdentifier")
    if isinstance(identifier, dict):
        return _str(identifier.get("PURL"))
    return None


def _vuln_finding(host: str, result: dict[str, Any], vuln: dict[str, Any]) -> Finding | None:
    vuln_id = _str(vuln.get("VulnerabilityID"))
    if vuln_id is None:
        return None
    pkg = _str(vuln.get("PkgName"))
    version = _str(vuln.get("InstalledVersion"))
    fixed = _str(vuln.get("FixedVersion"))
    score, vector = _best_cvss(vuln.get("CVSS"))
    cwes = [item for item in (vuln.get("CweIDs") or []) if isinstance(item, str)]
    metadata: dict[str, Any] = {
        "package": pkg,
        "package_version": version,
        "fixed_version": fixed,
        "target": _str(result.get("Target")),
        "type": _str(result.get("Type")),
        "purl": _purl(vuln),
    }
    return make_finding(
        source=SOURCE,
        host=host,
        title=vuln_id,
        severity=severity_from_label(vuln.get("Severity")),
        plugin_id=vuln_id,
        description=_str(vuln.get("Title")) or _str(vuln.get("Description")),
        solution=_solution(pkg, fixed),
        references=_references(vuln),
        cve_ids=(vuln_id,),  # non-CVE ids (GHSA/DLA/…) are filtered by normalization
        cwe_ids=cwes,
        cvss_score=score,
        cvss_vector=vector,
        metadata={key: value for key, value in metadata.items() if value is not None},
    )


def parse_trivy(document: object) -> list[Finding]:
    """Parse a loaded Trivy JSON report into normalized findings.

    ``host`` is the scanned artifact (``ArtifactName``, e.g. an image ref). Raises
    :class:`IngestError` if the document is not a Trivy report (no ``Results`` array).
    Findings are ordered by package then vulnerability id for deterministic output.
    """
    if not isinstance(document, dict):
        raise IngestError("Trivy report must be a JSON object")
    results = document.get("Results")
    if not isinstance(results, list):
        raise IngestError("Not a Trivy report: missing a 'Results' array")
    host = _str(document.get("ArtifactName")) or "unknown"
    findings: list[Finding] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        vulns = result.get("Vulnerabilities")
        if not isinstance(vulns, list):
            continue
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            finding = _vuln_finding(host, result, vuln)
            if finding is not None:
                findings.append(finding)
    findings.sort(
        key=lambda finding: (
            str(finding.metadata.get("package") or ""),
            finding.plugin_id or "",
            finding.title,
        )
    )
    return findings


__all__ = ["SOURCE", "parse_trivy"]
