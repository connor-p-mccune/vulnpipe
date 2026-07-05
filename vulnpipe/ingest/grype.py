"""Import a Grype JSON report into normalized findings.

Parses the JSON `Grype <https://github.com/anchore/grype>`_ emits (``grype -o json``)
-- a document of ``matches``, each pairing a ``vulnerability`` with the ``artifact``
(package) it affects -- into :class:`~vulnpipe.core.models.Finding` objects through
the shared :func:`~vulnpipe.processing.normalizer.make_finding` path. Severity comes
from Grype's own rating, the CVSS score/vector from the advisory's highest-scoring
entry, and the remediation line from the declared fix versions -- nothing invented, a
missing field left ``None``.

Package identity is carried in metadata, so imported findings feed the remediation
planner and the rest of the pipeline like any other. Pure and deterministic: findings
are ordered by package then vulnerability id.
"""

from typing import Any

from vulnpipe.core.models import Finding
from vulnpipe.ingest import IngestError, severity_from_label
from vulnpipe.processing.normalizer import make_finding, parse_cvss

#: ``Finding.source`` for Grype-imported findings.
SOURCE = "grype"


def _str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _host(source: Any) -> str:
    """The scanned subject: an image's user input, a scanned path, or ``unknown``."""
    if isinstance(source, dict):
        target = source.get("target")
        if isinstance(target, dict):
            return _str(target.get("userInput")) or _str(target.get("imageID")) or "unknown"
        if isinstance(target, str):
            return _str(target) or "unknown"
    return "unknown"


def _best_cvss(cvss: Any) -> tuple[float | None, str | None]:
    """Pick the highest CVSS base score (and its vector) among the advisory entries."""
    if not isinstance(cvss, list):
        return None, None
    best_score: float | None = None
    best_vector: str | None = None
    for entry in cvss:
        if not isinstance(entry, dict):
            continue
        metrics = entry.get("metrics")
        score = parse_cvss(metrics.get("baseScore")) if isinstance(metrics, dict) else None
        if score is not None and (best_score is None or score > best_score):
            best_score = score
            best_vector = _str(entry.get("vector"))
    return best_score, best_vector


def _fix_versions(vuln: dict[str, Any]) -> list[str]:
    fix = vuln.get("fix")
    if isinstance(fix, dict):
        versions = fix.get("versions")
        if isinstance(versions, list):
            return [item for item in versions if isinstance(item, str)]
    return []


def _references(vuln: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    data_source = _str(vuln.get("dataSource"))
    if data_source is not None:
        refs.append(data_source)
    urls = vuln.get("urls")
    if isinstance(urls, list):
        refs.extend(item for item in urls if isinstance(item, str))
    return refs


def _match_finding(host: str, match: dict[str, Any]) -> Finding | None:
    vuln = match.get("vulnerability")
    if not isinstance(vuln, dict):
        return None
    vuln_id = _str(vuln.get("id"))
    if vuln_id is None:
        return None
    raw_artifact = match.get("artifact")
    artifact: dict[str, Any] = raw_artifact if isinstance(raw_artifact, dict) else {}
    pkg = _str(artifact.get("name"))
    version = _str(artifact.get("version"))
    fixes = _fix_versions(vuln)
    solution = f"Update {pkg} to {', '.join(fixes)} or later." if pkg and fixes else None
    score, vector = _best_cvss(vuln.get("cvss"))
    metadata: dict[str, Any] = {
        "package": pkg,
        "package_version": version,
        "fixed_version": ", ".join(fixes) or None,
        "type": _str(artifact.get("type")),
        "purl": _str(artifact.get("purl")),
        "namespace": _str(vuln.get("namespace")),
    }
    return make_finding(
        source=SOURCE,
        host=host,
        title=vuln_id,
        severity=severity_from_label(vuln.get("severity")),
        plugin_id=vuln_id,
        description=_str(vuln.get("description")),
        solution=solution,
        references=_references(vuln),
        cve_ids=(vuln_id,),  # non-CVE ids (GHSA/…) are filtered by normalization
        cvss_score=score,
        cvss_vector=vector,
        metadata={key: value for key, value in metadata.items() if value is not None},
    )


def parse_grype(document: object) -> list[Finding]:
    """Parse a loaded Grype JSON report into normalized findings.

    ``host`` is the scanned image ref or path from ``source.target``. Raises
    :class:`IngestError` if the document is not a Grype report (no ``matches`` array).
    Findings are ordered by package then vulnerability id for deterministic output.
    """
    if not isinstance(document, dict):
        raise IngestError("Grype report must be a JSON object")
    matches = document.get("matches")
    if not isinstance(matches, list):
        raise IngestError("Not a Grype report: missing a 'matches' array")
    host = _host(document.get("source"))
    findings: list[Finding] = []
    for match in matches:
        if not isinstance(match, dict):
            continue
        finding = _match_finding(host, match)
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


__all__ = ["SOURCE", "parse_grype"]
