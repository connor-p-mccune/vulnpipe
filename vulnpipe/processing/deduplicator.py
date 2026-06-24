"""Collapse findings that share a fingerprint into a single, richer finding.

Two findings with the same :attr:`~vulnpipe.core.models.Finding.fingerprint`
describe the same underlying issue: the fingerprint hashes host, port, source,
plugin/alert id, and the normalized title. The same issue can legitimately surface
more than once -- a CVE reported by several Nmap NSE scripts, or one alert raised
on two spidered URLs that normalize to the same endpoint. This stage merges each
such group into one finding, keeping the richest detail the group offers so nothing
useful is dropped.

Pure function: findings in, findings out. The merge only touches fields that do not
feed the fingerprint, so the surviving finding keeps the group's identity and the
CI differ still recognizes it across runs. Merge rules:

* severity / confidence -> the highest present (worst case wins);
* references / CVE / CWE lists -> the de-duplicated union (order preserved);
* CVSS / EPSS scores -> the highest present value, leaving ``None`` only if every
  finding in the group was unknown (never invented);
* free-text detail -> the longest non-empty value;
* metadata -> the union, with earlier findings winning on key conflicts.
"""

from collections.abc import Iterable, Sequence
from typing import Any

from vulnpipe.core.models import Confidence, Finding
from vulnpipe.processing.normalizer import clean_cves, clean_tuple


def deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    """Collapse findings sharing a fingerprint, preserving first-seen order.

    Findings are grouped by fingerprint in the order each fingerprint first appears;
    every group is reduced to one finding via :func:`merge_findings`. A fingerprint
    seen only once passes through untouched (the same object is returned).
    """
    groups: dict[str, list[Finding]] = {}
    order: list[str] = []
    for finding in findings:
        bucket = groups.get(finding.fingerprint)
        if bucket is None:
            groups[finding.fingerprint] = [finding]
            order.append(finding.fingerprint)
        else:
            bucket.append(finding)

    merged: list[Finding] = []
    for fingerprint in order:
        bucket = groups[fingerprint]
        merged.append(bucket[0] if len(bucket) == 1 else merge_findings(bucket))
    return merged


def merge_findings(findings: Sequence[Finding]) -> Finding:
    """Merge findings that share a fingerprint into one, keeping the richest detail.

    The first finding supplies the identity (source, host, port, plugin id, title);
    every other field is folded across the whole group per the rules in the module
    docstring. Because no identity field changes, the merged finding's fingerprint
    equals the group's.
    """
    base = findings[0]
    updates: dict[str, Any] = {
        "severity": max((f.severity for f in findings), key=lambda s: s.rank),
        "confidence": _best_confidence(findings),
        "protocol": _first_present(f.protocol for f in findings),
        "description": _longest(f.description for f in findings),
        "solution": _longest(f.solution for f in findings),
        "evidence": _longest(f.evidence for f in findings),
        "references": clean_tuple(ref for f in findings for ref in f.references),
        "cve_ids": clean_cves(cve for f in findings for cve in f.cve_ids),
        "cwe_ids": clean_tuple(cwe for f in findings for cwe in f.cwe_ids),
        "cvss_score": _max_number(f.cvss_score for f in findings),
        "cvss_vector": _first_present(f.cvss_vector for f in findings),
        "epss_score": _max_number(f.epss_score for f in findings),
        "epss_percentile": _max_number(f.epss_percentile for f in findings),
        "metadata": _merge_metadata(findings),
    }
    return base.model_copy(update=updates)


def _best_confidence(findings: Sequence[Finding]) -> Confidence | None:
    present = [f.confidence for f in findings if f.confidence is not None]
    return max(present, key=lambda c: c.rank) if present else None


def _first_present(values: Iterable[str | None]) -> str | None:
    """First non-``None`` value, or ``None`` when every value is missing."""
    return next((value for value in values if value is not None), None)


def _longest(values: Iterable[str | None]) -> str | None:
    """Longest non-``None`` value, ties broken by first occurrence (the richest text)."""
    best: str | None = None
    for value in values:
        if value is not None and (best is None or len(value) > len(best)):
            best = value
    return best


def _max_number(values: Iterable[float | None]) -> float | None:
    present = [value for value in values if value is not None]
    return max(present) if present else None


def _merge_metadata(findings: Sequence[Finding]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for finding in findings:
        for key, value in finding.metadata.items():
            merged.setdefault(key, value)
    return merged


__all__ = ["deduplicate", "merge_findings"]
