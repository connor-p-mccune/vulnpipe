"""CycloneDX 1.5 vulnerability report (VDR) renderer.

Emits a `CycloneDX <https://cyclonedx.org>`_ 1.5 BOM whose ``vulnerabilities`` array
lists the known vulnerabilities vulnpipe detected, each linked to the component it
affects. This closes the supply-chain loop the SBOM layer opens: vulnpipe *consumes*
a CycloneDX SBOM (`vulnpipe sbom`) and now *emits* a CycloneDX Vulnerability
Disclosure Report, the format the CycloneDX ecosystem (Dependency-Track, `cyclonedx`
CLI, most SCA tooling) already ingests. It complements the OpenVEX reporter -- the
two are the dominant machine-readable vulnerability-exchange dialects -- so a run can
speak whichever one a downstream tool consumes.

Honest by construction, in the same spirit as the OpenVEX reporter:

* **Only known vulnerabilities.** A ``vulnerability`` entry is emitted for a finding
  that cites a real identifier -- a CVE, or (for a GHSA/OSV-only advisory from the
  SBOM layer) its OSV id. Open-port observations and hygiene alerts that name no such
  identifier produce nothing: a vulnerability report is about *vulnerabilities*.
* **No fabricated analysis.** CycloneDX's ``analysis.state`` (``exploitable`` /
  ``not_affected`` / ``in_triage`` / …) is a human triage judgement. vulnpipe
  *detected* each issue but has not assessed its exploitability, so no ``analysis``
  block is written -- claiming a triage state would invent an assessment. That makes
  this a disclosure report (VDR), not a full VEX.
* **Ratings only when scored.** A ``rating`` always carries the finding's real
  qualitative ``severity``; the numeric ``score`` / ``method`` / ``vector`` appear
  only when a real CVSS vector/score is known, never a guessed one.

Deterministic for fixed input like every reporter: components are sorted by
``bom-ref``, vulnerabilities follow first-seen id order, and ``affects`` / ``cwes`` /
``advisories`` are sorted. The ``serialNumber`` is content-addressed (a hash of the
components + vulnerabilities), so identical findings always yield the same document.
The one non-derivable field is ``metadata.timestamp``: the pure builders omit it,
while the registered reporter stamps real UTC time honoring ``SOURCE_DATE_EPOCH`` so
CI can emit byte-identical documents.
"""

import hashlib
import json
import os
import re
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from vulnpipe import __version__
from vulnpipe.core.models import Finding, Severity
from vulnpipe.core.standards import parse_cwe
from vulnpipe.reporting.base import BaseReporter

#: CycloneDX spec version this reporter targets.
SPEC_VERSION = "1.5"

#: RFC 3339 UTC layout for the BOM metadata timestamp.
_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_GHSA_RE = re.compile(r"^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$", re.IGNORECASE)

#: vulnpipe severity -> CycloneDX rating severity vocabulary.
_CDX_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFORMATIONAL: "info",
}


def _vuln_ids(finding: Finding) -> tuple[str, ...]:
    """The vulnerability identifiers a finding is reported under.

    Prefers CVEs (the canonical id); an advisory with no CVE (a GHSA/OSV-only OSV
    record from the SBOM layer) falls back to its OSV id. A finding citing no
    identifier yields nothing and produces no vulnerability entry.
    """
    if finding.cve_ids:
        return finding.cve_ids
    osv_id = finding.metadata.get("osv_id")
    if isinstance(osv_id, str) and osv_id:
        return (osv_id,)
    return ()


def _source(vuln_id: str) -> dict[str, str]:
    """The advisory ``source`` (database name + canonical URL) for an identifier."""
    if _CVE_RE.match(vuln_id):
        return {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{vuln_id}"}
    if _GHSA_RE.match(vuln_id):
        return {
            "name": "GitHub Advisory Database",
            "url": f"https://github.com/advisories/{vuln_id}",
        }
    return {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vuln_id}"}


def _meta_str(finding: Finding, key: str) -> str | None:
    value = finding.metadata.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _component(finding: Finding) -> tuple[str, dict[str, Any]]:
    """The affected component ``(bom-ref, component)`` a finding pertains to.

    A supply-chain finding with a package URL is a ``library`` keyed by its purl; a
    network/web finding is the affected asset, an ``application`` keyed by
    ``host[:port]`` -- so the ``affects`` links resolve to a real BOM component.
    """
    purl = _meta_str(finding, "purl")
    if purl is not None:
        component: dict[str, Any] = {"type": "library", "bom-ref": purl, "purl": purl}
        name = _meta_str(finding, "package")
        version = _meta_str(finding, "package_version")
        component["name"] = name if name is not None else purl
        if version is not None:
            component["version"] = version
        return purl, component
    ref = finding.host if finding.port is None else f"{finding.host}:{finding.port}"
    return ref, {"type": "application", "bom-ref": ref, "name": finding.host}


def _cvss_method(vector: str | None) -> str:
    """Map a CVSS vector onto the CycloneDX rating ``method`` vocabulary."""
    if vector is None:
        return "other"
    prefix = vector.strip().upper()
    if prefix.startswith("CVSS:4.0"):
        return "CVSSv4"
    if prefix.startswith("CVSS:3.1"):
        return "CVSSv31"
    if prefix.startswith("CVSS:3.0"):
        return "CVSSv3"
    if prefix.startswith("AV:"):  # a v2 vector carries no CVSS: prefix
        return "CVSSv2"
    return "other"


def _rating(finding: Finding) -> dict[str, Any]:
    """The CycloneDX ``rating`` for a finding: always qualitative, numeric when known."""
    rating: dict[str, Any] = {
        "source": {"name": "vulnpipe"},
        "severity": _CDX_SEVERITY[finding.severity],
    }
    if finding.cvss_score is not None:
        rating["score"] = finding.cvss_score
        rating["method"] = _cvss_method(finding.cvss_vector)
        if finding.cvss_vector:
            rating["vector"] = finding.cvss_vector
    return rating


def _advisories(findings: Iterable[Finding]) -> list[dict[str, str]]:
    """Distinct http(s) reference URLs across ``findings``, sorted."""
    urls: set[str] = set()
    for finding in findings:
        for reference in finding.references:
            if reference.startswith(("http://", "https://")):
                urls.add(reference)
    return [{"url": url} for url in sorted(urls)]


def _cwes(findings: Iterable[Finding]) -> list[int]:
    """Distinct CWE numbers across ``findings``, sorted (unparseable ones dropped)."""
    numbers: set[int] = set()
    for finding in findings:
        for cwe in finding.cwe_ids:
            parsed = parse_cwe(cwe)
            if parsed is not None:
                numbers.add(parsed)
    return sorted(numbers)


def _representative(findings: list[Finding]) -> Finding:
    """The finding that describes/rates a grouped vulnerability: worst risk wins."""
    return max(findings, key=lambda finding: (finding.risk_score, finding.fingerprint))


def _vulnerability(vuln_id: str, findings: list[Finding], refs: set[str]) -> dict[str, Any]:
    """Assemble one CycloneDX ``vulnerability`` from every finding citing ``vuln_id``."""
    rep = _representative(findings)
    entry: dict[str, Any] = {"bom-ref": vuln_id, "id": vuln_id, "source": _source(vuln_id)}
    entry["ratings"] = [_rating(rep)]
    cwes = _cwes(findings)
    if cwes:
        entry["cwes"] = cwes
    if rep.description:
        entry["description"] = rep.description
    if rep.solution:
        entry["recommendation"] = rep.solution
    advisories = _advisories(findings)
    if advisories:
        entry["advisories"] = advisories
    entry["affects"] = [{"ref": ref} for ref in sorted(refs)]
    properties = [
        {"name": "vulnpipe:risk_score", "value": str(max(f.risk_score for f in findings))},
        {"name": "vulnpipe:kev", "value": "true" if any(f.kev for f in findings) else "false"},
    ]
    if rep.epss_score is not None:
        properties.append({"name": "vulnpipe:epss", "value": f"{rep.epss_score:.5f}"})
    entry["properties"] = properties
    return entry


def _serial_number(components: list[Any], vulnerabilities: list[Any]) -> str:
    """A content-addressed ``urn:uuid`` derived from the BOM's substantive content."""
    canonical = json.dumps(
        {"components": components, "vulnerabilities": vulnerabilities},
        sort_keys=True,
        ensure_ascii=False,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"urn:uuid:{digest[0:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


def _format_timestamp(timestamp: str | datetime | None) -> str | None:
    """Normalize a caller-supplied timestamp to an RFC 3339 UTC string, or ``None``."""
    if timestamp is None:
        return None
    if isinstance(timestamp, datetime):
        moment = timestamp if timestamp.tzinfo is not None else timestamp.replace(tzinfo=UTC)
        return moment.astimezone(UTC).strftime(_TIMESTAMP_FORMAT)
    return timestamp


def _publication_timestamp() -> str:
    """The publication timestamp the registered reporter stamps documents with.

    Honors ``SOURCE_DATE_EPOCH`` (reproducible builds) when set, otherwise current
    UTC time. A malformed override is an error, not silently ignored.
    """
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch is not None:
        try:
            seconds = int(epoch)
        except ValueError as exc:
            raise ValueError(
                f"SOURCE_DATE_EPOCH must be an integer Unix timestamp, got {epoch!r}"
            ) from exc
        return datetime.fromtimestamp(seconds, tz=UTC).strftime(_TIMESTAMP_FORMAT)
    return datetime.now(tz=UTC).strftime(_TIMESTAMP_FORMAT)


def build_cyclonedx(
    findings: Iterable[Finding], *, timestamp: str | datetime | None = None
) -> dict[str, Any]:
    """Build the CycloneDX 1.5 VDR document for ``findings``.

    Findings are grouped into one ``vulnerability`` per identifier (a CVE seen on
    several hosts, or shared by an SBOM component and a network service, becomes one
    entry with several ``affects``); only components referenced by a listed
    vulnerability appear in ``components``.
    """
    items = list(findings)

    order: list[str] = []
    by_vuln: dict[str, list[Finding]] = {}
    affects: dict[str, set[str]] = {}
    components: dict[str, dict[str, Any]] = {}
    for finding in items:
        vuln_ids = _vuln_ids(finding)
        if not vuln_ids:
            continue
        ref, component = _component(finding)
        components.setdefault(ref, component)
        for vuln_id in vuln_ids:
            if vuln_id not in by_vuln:
                order.append(vuln_id)
                by_vuln[vuln_id] = []
                affects[vuln_id] = set()
            by_vuln[vuln_id].append(finding)
            affects[vuln_id].add(ref)

    component_list = [components[ref] for ref in sorted(components)]
    vulnerabilities = [
        _vulnerability(vuln_id, by_vuln[vuln_id], affects[vuln_id]) for vuln_id in order
    ]

    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": _serial_number(component_list, vulnerabilities),
        "version": 1,
    }
    metadata: dict[str, Any] = {}
    stamped = _format_timestamp(timestamp)
    if stamped is not None:
        metadata["timestamp"] = stamped
    metadata["tools"] = {
        "components": [{"type": "application", "name": "vulnpipe", "version": __version__}]
    }
    document["metadata"] = metadata
    document["components"] = component_list
    document["vulnerabilities"] = vulnerabilities
    return document


def render_cyclonedx(
    findings: Iterable[Finding], *, timestamp: str | datetime | None = None
) -> str:
    """Render ``findings`` into a deterministic CycloneDX 1.5 VDR JSON string."""
    document = build_cyclonedx(findings, timestamp=timestamp)
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


class CyclonedxReporter(BaseReporter):
    """Render findings into a CycloneDX 1.5 vulnerability report stamped at publish time.

    The path the CLI publishes through, so the ``metadata.timestamp`` is always
    present (from ``SOURCE_DATE_EPOCH`` when set, otherwise current UTC time);
    everything else is a pure function of the findings (see :func:`build_cyclonedx`).
    """

    name = "cyclonedx"

    def render(self, findings: list[Finding]) -> str:
        return render_cyclonedx(findings, timestamp=_publication_timestamp())


__all__ = [
    "SPEC_VERSION",
    "CyclonedxReporter",
    "build_cyclonedx",
    "render_cyclonedx",
]
