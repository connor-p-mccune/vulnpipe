"""Unit tests for fingerprint-based finding deduplication."""

from typing import Any

from vulnpipe.core.models import Confidence, Finding, Severity
from vulnpipe.processing.deduplicator import deduplicate, merge_findings
from vulnpipe.processing.normalizer import make_finding

# A fixed identity (host/port/source/plugin/title) so variants share a fingerprint.
_IDENTITY: dict[str, Any] = {
    "source": "zap",
    "host": "10.0.0.5",
    "port": 443,
    "plugin_id": "40012",
    "title": "SQL Injection",
}


def _variant(**overrides: Any) -> Finding:
    params: dict[str, Any] = {**_IDENTITY}
    params.update(overrides)
    return make_finding(**params)


def test_deduplicate_collapses_same_fingerprint() -> None:
    a = _variant(severity=Severity.LOW)
    b = _variant(severity=Severity.HIGH)
    assert a.fingerprint == b.fingerprint  # same underlying issue
    result = deduplicate([a, b])
    assert len(result) == 1
    assert result[0].fingerprint == a.fingerprint


def test_deduplicate_keeps_distinct_findings_in_order() -> None:
    a = _variant(title="SQL Injection")
    b = _variant(title="Reflected XSS")  # different title -> different fingerprint
    c = make_finding(source="nmap", host="10.0.0.6", title="Open port 22/tcp")
    result = deduplicate([a, b, c])
    assert [f.title for f in result] == ["SQL Injection", "Reflected XSS", "Open port 22/tcp"]


def test_deduplicate_singleton_returns_same_object() -> None:
    finding = _variant()
    result = deduplicate([finding])
    assert result[0] is finding  # nothing to merge -> untouched


def test_deduplicate_preserves_first_seen_order() -> None:
    first = make_finding(source="nmap", host="a", title="A")
    second = make_finding(source="nmap", host="b", title="B")
    # B seen, then A duplicated, then B duplicated: order follows first appearance.
    result = deduplicate([second, first, second, first])
    assert [f.host for f in result] == ["b", "a"]


def test_merge_keeps_richest_detail() -> None:
    a = _variant(
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        description="short",
        references=["https://a"],
        cve_ids=["CVE-2021-0001"],
        cwe_ids=["89"],
        cvss_score=5.0,
    )
    b = _variant(
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="a considerably more detailed description",
        references=["https://b"],
        cve_ids=["CVE-2021-0002"],
        cwe_ids=["79"],
        cvss_score=9.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    merged = merge_findings([a, b])
    assert merged.severity is Severity.HIGH  # worst case wins
    assert merged.confidence is Confidence.HIGH
    assert merged.description == "a considerably more detailed description"  # longest text
    assert merged.references == ("https://a", "https://b")  # union, order preserved
    assert merged.cve_ids == ("CVE-2021-0001", "CVE-2021-0002")
    assert merged.cwe_ids == ("89", "79")
    assert merged.cvss_score == 9.1  # highest present
    assert merged.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # filled


def test_merge_fills_missing_scores_without_inventing() -> None:
    a = _variant(cvss_score=None, epss_score=None)
    b = _variant(cvss_score=7.5, epss_score=0.4)
    merged = merge_findings([a, b])
    assert merged.cvss_score == 7.5  # gap filled from the other finding
    assert merged.epss_score == 0.4
    # When the whole group is unknown the field stays unknown (never guessed).
    both_unknown = merge_findings([_variant(cvss_score=None), _variant(cvss_score=None)])
    assert both_unknown.cvss_score is None


def test_merge_preserves_fingerprint() -> None:
    a = _variant(severity=Severity.LOW, cve_ids=["CVE-2021-0001"])
    b = _variant(severity=Severity.CRITICAL, cve_ids=["CVE-2021-0002"])
    merged = merge_findings([a, b])
    assert merged.fingerprint == a.fingerprint  # identity (and thus diffing) is stable


def test_merge_unions_metadata_first_wins() -> None:
    a = _variant(metadata={"k": "from-a", "only_a": 1})
    b = _variant(metadata={"k": "from-b", "only_b": 2})
    merged = merge_findings([a, b])
    assert merged.metadata == {"k": "from-a", "only_a": 1, "only_b": 2}


def test_deduplicate_empty() -> None:
    assert deduplicate([]) == []


def test_deduplicate_does_not_mutate_input() -> None:
    findings = [_variant(severity=Severity.LOW), _variant(severity=Severity.HIGH)]
    snapshot = list(findings)
    deduplicate(findings)
    assert findings == snapshot  # input list untouched
