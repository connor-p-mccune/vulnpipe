"""SARIF 2.1.0 report renderer.

Emits SARIF 2.1.0 so findings can be uploaded to GitHub code scanning (the
Security tab) and other SARIF-aware dashboards. The output is a single ``run`` with
one ``reportingDescriptor`` (rule) per distinct scanner check and one ``result`` per
finding.

A few deliberate choices make the output useful and honest:

* **Stable result identity.** Each result carries the finding's vulnpipe
  fingerprint under ``partialFingerprints`` so the dashboard tracks the same issue
  across runs rather than treating every scan as brand new.
* **Severity.** ``result.level`` is SARIF's native severity (error/warning/note/
  none) mapped from the normalized :class:`~vulnpipe.core.models.Severity`. The
  GitHub Security tab additionally ranks by a ``security-severity`` number on the
  rule; that number is the finding's real CVSS base score when one is known, and
  otherwise the lower bound of its severity band -- a presentation-only ranking
  hint, never written back onto the finding (the canonical JSON keeps an unknown
  CVSS as ``null``). Nothing here fabricates a CVSS score.

Deterministic for fixed input: rules appear in first-seen order, results follow the
given (prioritized) finding order, and no timestamp is embedded.
"""

import json
import re
from collections.abc import Iterable
from typing import Any

from vulnpipe import __version__
from vulnpipe.core.models import Finding, Severity
from vulnpipe.core.standards import owasp_categories
from vulnpipe.reporting.base import BaseReporter

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_NON_SLUG = re.compile(r"[^a-z0-9]+")

# Normalized severity -> SARIF result level.
_LEVEL_BY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFORMATIONAL: "none",
}

# Lower bound of each severity band on GitHub's security-severity scale, used only
# when a finding has no real CVSS score to report (dashboard ranking hint).
_SECURITY_SEVERITY_FLOOR: dict[Severity, float] = {
    Severity.CRITICAL: 9.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 4.0,
    Severity.LOW: 0.1,
    Severity.INFORMATIONAL: 0.0,
}


def _slug(text: str) -> str:
    """A lowercase ``a-z0-9-`` slug, used to build a rule id from a title."""
    return _NON_SLUG.sub("-", text.lower()).strip("-") or "finding"


def _rule_id(finding: Finding) -> str:
    """Stable rule id for a finding: ``<source>/<plugin id or title slug>``."""
    return f"{finding.source}/{finding.plugin_id or _slug(finding.title)}"


def _security_severity(finding: Finding) -> float:
    """The GitHub ``security-severity`` number for a finding (see the module docstring)."""
    if finding.cvss_score is not None:
        return finding.cvss_score
    return _SECURITY_SEVERITY_FLOOR[finding.severity]


def _format_security_severity(value: float) -> str:
    """Format a security-severity number as the single-decimal string GitHub expects."""
    return f"{value:.1f}"


def _message_text(finding: Finding) -> str:
    """Result message: the title, with any CVE ids appended for context."""
    if finding.cve_ids:
        return f"{finding.title} ({', '.join(finding.cve_ids)})"
    return finding.title


def _location(finding: Finding) -> dict[str, Any]:
    """Build a SARIF location from the finding's URL (web) or host:port (network)."""
    url = finding.metadata.get("url")
    host_port = finding.host if finding.port is None else f"{finding.host}:{finding.port}"
    uri = url if isinstance(url, str) and url else host_port
    return {
        "physicalLocation": {"artifactLocation": {"uri": uri}},
        "logicalLocations": [{"fullyQualifiedName": host_port, "kind": "module"}],
    }


def _rule_tags(finding: Finding) -> list[str]:
    """Rule tags: the ``security`` marker GitHub keys on, CWE references, and the
    OWASP Top 10 categories those CWEs map to (in the ``external/...`` convention)."""
    tags = ["security", *(f"external/cwe/{cwe}" for cwe in finding.cwe_ids)]
    tags.extend(
        f"external/owasp/{category.id.lower()}" for category in owasp_categories(finding.cwe_ids)
    )
    return tags


def _build_rule(rule_id: str, finding: Finding, security_severity: float) -> dict[str, Any]:
    """Build the ``reportingDescriptor`` (rule) for a finding's check."""
    properties: dict[str, Any] = {
        "tags": _rule_tags(finding),
        "security-severity": _format_security_severity(security_severity),
    }
    rule: dict[str, Any] = {
        "id": rule_id,
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "properties": properties,
    }
    if finding.description:
        rule["fullDescription"] = {"text": finding.description}
    if finding.references:
        rule["helpUri"] = finding.references[0]
    if finding.solution:
        rule["help"] = {"text": finding.solution}
    return rule


def _build_result(finding: Finding, rule_id: str, rule_index: int) -> dict[str, Any]:
    """Build the SARIF ``result`` for a single finding."""
    properties: dict[str, Any] = {
        "severity": finding.severity.value,
        "source": finding.source,
        "riskScore": finding.risk_score,
    }
    if finding.kev:
        properties["kev"] = True
    if finding.cvss_score is not None:
        properties["cvssScore"] = finding.cvss_score
    if finding.epss_score is not None:
        properties["epssScore"] = finding.epss_score
    if finding.cve_ids:
        properties["cves"] = list(finding.cve_ids)
    categories = owasp_categories(finding.cwe_ids)
    if categories:
        properties["owasp"] = [category.id for category in categories]
    return {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": _LEVEL_BY_SEVERITY[finding.severity],
        "message": {"text": _message_text(finding)},
        "locations": [_location(finding)],
        "partialFingerprints": {"vulnpipeFingerprint/v1": finding.fingerprint},
        "properties": properties,
    }


def build_sarif(findings: Iterable[Finding]) -> dict[str, Any]:
    """Build the full SARIF 2.1.0 document for ``findings``.

    Rules are collected in first-seen order and de-duplicated by id; when several
    findings share a rule the rule keeps the worst-case ``security-severity``.
    Results follow the order of ``findings``.
    """
    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        rule_id = _rule_id(finding)
        security_severity = _security_severity(finding)
        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            rules.append(_build_rule(rule_id, finding, security_severity))
        else:
            rule = rules[rule_index[rule_id]]
            current = float(rule["properties"]["security-severity"])
            if security_severity > current:
                rule["properties"]["security-severity"] = _format_security_severity(
                    security_severity
                )
        results.append(_build_result(finding, rule_id, rule_index[rule_id]))

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vulnpipe",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


class SarifReporter(BaseReporter):
    """Render findings into a deterministic SARIF 2.1.0 document."""

    name = "sarif"

    def render(self, findings: list[Finding]) -> str:
        return json.dumps(build_sarif(findings), indent=2, ensure_ascii=False) + "\n"


__all__ = [
    "SARIF_SCHEMA",
    "SARIF_VERSION",
    "SarifReporter",
    "build_sarif",
]
