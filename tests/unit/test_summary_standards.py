"""Unit tests for the standards view-model (`summarize_standards` / `finding_owasp`).

These pure helpers back the OWASP Top 10 sections across the report formats, so
they are covered directly: multi-category counting, the uncategorized bucket, the
CWE Top 25 tally, and the fixed rank ordering reporters rely on.
"""

from vulnpipe.core.models import Finding, Severity
from vulnpipe.processing.normalizer import make_finding
from vulnpipe.reporting.summary import finding_owasp, summarize_standards


def _finding(cwe_ids: list[str], title: str = "issue") -> Finding:
    return make_finding(
        source="zap", host="app.example.com", title=title, severity=Severity.MEDIUM, cwe_ids=cwe_ids
    )


def test_finding_owasp_maps_cwes_in_rank_order() -> None:
    finding = _finding(["CWE-918", "CWE-79"])
    assert [category.short for category in finding_owasp(finding)] == ["A03", "A10"]


def test_finding_owasp_empty_for_unmapped_or_missing_cwes() -> None:
    assert finding_owasp(_finding([])) == ()
    assert finding_owasp(_finding(["CWE-99999"])) == ()


def test_summarize_counts_each_category_a_finding_touches() -> None:
    findings = [
        _finding(["CWE-79"], "xss"),  # A03
        _finding(["CWE-89"], "sqli"),  # A03
        _finding(["CWE-918", "CWE-79"], "ssrf+xss"),  # A03 and A10
        _finding([], "no cwe"),  # uncategorized
    ]
    standards = summarize_standards(findings)
    by_short = {category.short: count for category, count in standards.owasp.items()}
    assert by_short["A03"] == 3
    assert by_short["A10"] == 1
    assert by_short["A01"] == 0  # zero bands stay present (fixed shape)
    assert standards.uncategorized == 1
    assert standards.any_mapped is True


def test_summarize_owasp_keys_are_in_rank_order() -> None:
    standards = summarize_standards([])
    assert [category.rank for category in standards.owasp] == list(range(1, 11))
    assert standards.any_mapped is False
    assert standards.uncategorized == 0


def test_cwe_top_25_counts_findings_not_weaknesses() -> None:
    findings = [
        _finding(["CWE-79", "CWE-89"], "two top-25 cwes"),  # one finding
        _finding(["CWE-1275"], "not top 25"),
    ]
    assert summarize_standards(findings).cwe_top_25 == 1


def test_unmapped_cwe_lands_in_uncategorized() -> None:
    standards = summarize_standards([_finding(["CWE-99999"])])
    assert standards.uncategorized == 1
    assert standards.any_mapped is False
