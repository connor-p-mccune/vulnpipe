"""GitLab security report renderer.

Emits a GitLab-compatible security report -- the JSON GitLab ingests to populate
its Vulnerability Report and the merge-request security widget. SARIF already feeds
the GitHub Security tab; this feeds the other dominant CI platform, so a single
vulnpipe scan surfaces natively in either pipeline.

vulnpipe is fundamentally a *dynamic* scanner -- it probes running hosts and web
applications -- so findings are exported as a DAST-style report
(``scan.type: dast``); supply-chain findings still map cleanly, keyed by their SBOM
subject as the location hostname.

Honest, deterministic choices, as everywhere else:

* the vulnerability ``id`` is the finding's stable fingerprint, so GitLab tracks the
  same issue across pipelines instead of re-opening it every run;
* ``identifiers`` carry the real CVEs and CWEs a finding cites (each with its
  canonical URL) plus a vulnpipe rule identifier, so a finding with no CVE still has
  a stable identifier and the list is never empty (GitLab requires at least one);
* ``severity`` maps the normalized band onto GitLab's vocabulary; a description or
  ``solution`` is emitted only when the scanner provided one -- nothing is invented.

Determinism: vulnerabilities follow the given (prioritized) order and no value is
fabricated. GitLab's schema requires ``scan.start_time`` / ``scan.end_time``; like
the OpenVEX publication timestamp those are the one non-derivable field --
:func:`build_gitlab_report` omits them unless passed (so snapshot tests stay stable),
while the registered reporter stamps them, honoring the reproducible-builds
``SOURCE_DATE_EPOCH`` convention.
"""

import json
import os
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from vulnpipe import __version__
from vulnpipe.core.models import Finding, Severity
from vulnpipe.core.standards import parse_cwe
from vulnpipe.reporting.base import BaseReporter

#: The GitLab security report schema version this output targets.
GITLAB_SCHEMA_VERSION = "15.0.6"

#: The scan type vulnpipe reports under (a dynamic scanner probing running systems).
GITLAB_SCAN_TYPE = "dast"

#: ``strftime`` layout for GitLab's ``start_time`` / ``end_time`` (no timezone suffix).
_SCAN_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

#: Normalized severity -> GitLab severity vocabulary.
_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFORMATIONAL: "Info",
}

#: How many reference links to carry onto a vulnerability.
_MAX_LINKS = 10


def _tool() -> dict[str, Any]:
    """The analyzer/scanner identity block GitLab records for provenance."""
    return {
        "id": "vulnpipe",
        "name": "vulnpipe",
        "version": __version__,
        "vendor": {"name": "vulnpipe"},
    }


def _rule_identifier(finding: Finding) -> dict[str, str]:
    """A stable vulnpipe rule identifier, so every vulnerability has one.

    Keyed on ``<source>/<plugin id>`` (falling back to the title) -- present even
    when a finding cites no CVE, which GitLab needs as the primary identifier.
    """
    value = f"{finding.source}/{finding.plugin_id or finding.title}"
    return {"type": "vulnpipe_rule", "name": value, "value": value}


def _identifiers(finding: Finding) -> list[dict[str, str]]:
    """The finding's identifiers: CVEs, then CWEs, then the vulnpipe rule id.

    CVEs lead so GitLab treats the canonical vulnerability id as primary; a
    trailing vulnpipe rule id guarantees the list is never empty.
    """
    identifiers: list[dict[str, str]] = []
    for cve in finding.cve_ids:
        identifiers.append(
            {
                "type": "cve",
                "name": cve,
                "value": cve,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
            }
        )
    for raw in finding.cwe_ids:
        number = parse_cwe(raw)
        if number is None:
            continue
        identifiers.append(
            {
                "type": "cwe",
                "name": f"CWE-{number}",
                "value": str(number),
                "url": f"https://cwe.mitre.org/data/definitions/{number}.html",
            }
        )
    identifiers.append(_rule_identifier(finding))
    return identifiers


def _location(finding: Finding) -> dict[str, str]:
    """A GitLab DAST location: the hostname and path, plus method/param when known."""
    url = finding.metadata.get("url")
    if isinstance(url, str) and url:
        parsed = urlparse(url)
        location: dict[str, str] = {
            "hostname": parsed.hostname or finding.host,
            "path": parsed.path or "/",
        }
    else:
        location = {"hostname": finding.host, "path": "/"}
    method = finding.metadata.get("method")
    if isinstance(method, str) and method:
        location["method"] = method
    param = finding.metadata.get("param")
    if isinstance(param, str) and param:
        location["param"] = param
    return location


def _links(finding: Finding) -> list[dict[str, str]]:
    """External reference links (http(s) only), capped to keep the report compact."""
    links = [
        {"url": ref}
        for ref in finding.references
        if ref.startswith("http://") or ref.startswith("https://")
    ]
    return links[:_MAX_LINKS]


def _vulnerability(finding: Finding) -> dict[str, Any]:
    """Build one GitLab ``vulnerabilities[]`` entry from a finding."""
    vulnerability: dict[str, Any] = {
        "id": finding.fingerprint,
        "name": finding.title,
        "severity": _SEVERITY[finding.severity],
        "identifiers": _identifiers(finding),
        "location": _location(finding),
    }
    if finding.description:
        vulnerability["description"] = finding.description
    if finding.solution:
        vulnerability["solution"] = finding.solution
    links = _links(finding)
    if links:
        vulnerability["links"] = links
    return vulnerability


def build_gitlab_report(
    findings: Iterable[Finding], *, timestamp: str | None = None
) -> dict[str, Any]:
    """Build the GitLab security report document for ``findings``.

    Vulnerabilities keep the given (prioritized) order. ``timestamp`` fills the
    schema-required ``scan.start_time`` / ``scan.end_time``; it is omitted when not
    supplied so the pure output stays snapshot-stable (the reporter always stamps it).
    """
    scan: dict[str, Any] = {
        "analyzer": _tool(),
        "scanner": _tool(),
        "type": GITLAB_SCAN_TYPE,
        "status": "success",
    }
    if timestamp is not None:
        scan["start_time"] = timestamp
        scan["end_time"] = timestamp
    return {
        "version": GITLAB_SCHEMA_VERSION,
        "scan": scan,
        "vulnerabilities": [_vulnerability(finding) for finding in findings],
    }


def _scan_timestamp() -> str:
    """The scan timestamp the registered reporter stamps the report with.

    Honors ``SOURCE_DATE_EPOCH`` (seconds since the Unix epoch) when set so CI can
    emit byte-identical reports; otherwise the current UTC time. A malformed override
    is an error, not silently ignored.
    """
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch is not None:
        try:
            seconds = int(epoch)
        except ValueError as exc:
            raise ValueError(
                f"SOURCE_DATE_EPOCH must be an integer Unix timestamp, got {epoch!r}"
            ) from exc
        return datetime.fromtimestamp(seconds, tz=UTC).strftime(_SCAN_TIME_FORMAT)
    return datetime.now(tz=UTC).strftime(_SCAN_TIME_FORMAT)


def render_gitlab(findings: Iterable[Finding], *, timestamp: str | None = None) -> str:
    """Render ``findings`` into a GitLab security report JSON string."""
    report = build_gitlab_report(findings, timestamp=timestamp)
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


class GitlabReporter(BaseReporter):
    """Render findings into a GitLab-compatible security report.

    This is the path the CLI writes through, so the schema-required scan times are
    always present: from ``SOURCE_DATE_EPOCH`` when set (reproducible builds),
    otherwise the current UTC time. Everything else is a pure function of the
    findings (see :func:`build_gitlab_report`).
    """

    name = "gitlab"

    def render(self, findings: list[Finding]) -> str:
        return render_gitlab(findings, timestamp=_scan_timestamp())


__all__ = [
    "GITLAB_SCAN_TYPE",
    "GITLAB_SCHEMA_VERSION",
    "GitlabReporter",
    "build_gitlab_report",
    "render_gitlab",
]
