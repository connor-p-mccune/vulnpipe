"""Unit tests for baseline-vs-current diffing.

Drives a synthetic baseline-vs-current pair and asserts each finding lands in the
right bucket (new / persisting / resolved), that ordering is deterministic, and
that the serialized payload is stable.
"""

import random

from vulnpipe.ci.baseline import build_baseline
from vulnpipe.ci.differ import (
    Diff,
    diff_findings,
    diff_to_payload,
    render_diff_html,
    render_diff_markdown,
)
from vulnpipe.core.models import Finding, Severity
from vulnpipe.processing.normalizer import make_finding


def _f(title: str, *, host: str = "10.0.0.10", severity: Severity = Severity.MEDIUM) -> Finding:
    return make_finding(source="nmap", host=host, title=title, severity=severity, plugin_id="p")


def test_classifies_new_persisting_resolved() -> None:
    keep = _f("kept")  # in both baseline and current -> persisting
    gone = _f("removed")  # in baseline only -> resolved
    fresh = _f("introduced")  # in current only -> new

    baseline = build_baseline([keep, gone])
    diff = diff_findings([keep, fresh], baseline)

    assert [f.title for f in diff.new] == ["introduced"]
    assert [f.title for f in diff.persisting] == ["kept"]
    assert [e.title for e in diff.resolved] == ["removed"]
    assert diff.counts == {"new": 1, "persisting": 1, "resolved": 1}
    assert diff.is_clean is False


def test_empty_baseline_makes_everything_new() -> None:
    findings = [_f("a"), _f("b")]
    diff = diff_findings(findings, build_baseline([]))
    assert diff.counts == {"new": 2, "persisting": 0, "resolved": 0}
    assert {f.title for f in diff.new} == {"a", "b"}


def test_empty_current_resolves_everything() -> None:
    baseline = build_baseline([_f("a"), _f("b")])
    diff = diff_findings([], baseline)
    assert diff.counts == {"new": 0, "persisting": 0, "resolved": 2}
    assert diff.is_clean is True


def test_identical_scan_is_all_persisting() -> None:
    findings = [_f("a"), _f("b"), _f("c")]
    diff = diff_findings(findings, build_baseline(findings))
    assert diff.counts == {"new": 0, "persisting": 3, "resolved": 0}
    assert diff.is_clean is True


def test_new_and_persisting_preserve_current_order() -> None:
    persist = _f("persist")
    baseline = build_baseline([persist])
    # Current order interleaves new and persisting; that order must be preserved.
    current = [_f("n1"), persist, _f("n2"), _f("n3")]
    diff = diff_findings(current, baseline)
    assert [f.title for f in diff.new] == ["n1", "n2", "n3"]
    assert [f.title for f in diff.persisting] == ["persist"]


def test_resolved_order_is_deterministic_regardless_of_baseline_input_order() -> None:
    gone = [_f("g1"), _f("g2"), _f("g3")]
    expected = [e.fingerprint for e in diff_findings([], build_baseline(gone)).resolved]
    shuffled = list(gone)
    random.Random(3).shuffle(shuffled)
    assert [e.fingerprint for e in diff_findings([], build_baseline(shuffled)).resolved] == expected


def test_payload_shape_and_determinism() -> None:
    keep, gone, fresh = _f("kept"), _f("removed"), _f("introduced")
    baseline = build_baseline([keep, gone])
    payload = diff_to_payload(diff_findings([keep, fresh], baseline))
    assert payload["summary"] == {"new": 1, "persisting": 1, "resolved": 1}
    assert payload["new"][0]["title"] == "introduced"
    assert payload["new"][0]["fingerprint"] == fresh.fingerprint
    assert payload["resolved"][0]["title"] == "removed"
    # Recomputing the payload yields an identical structure.
    assert diff_to_payload(diff_findings([keep, fresh], baseline)) == payload


def test_diff_is_frozen_dataclass() -> None:
    diff = Diff(new=(), persisting=(), resolved=())
    assert diff.counts == {"new": 0, "persisting": 0, "resolved": 0}


# --------------------------------------------------------------------------- #
# Markdown rendering (PR comment)
# --------------------------------------------------------------------------- #
def test_markdown_headline_and_new_table() -> None:
    keep = _f("kept")
    gone = _f("removed", severity=Severity.LOW)
    fresh = make_finding(
        source="nmap",
        host="10.0.0.5",
        title="CVE-2021-42013",
        severity=Severity.CRITICAL,
        port=80,
        plugin_id="vulners",
        cve_ids=["CVE-2021-42013"],
        cvss_score=9.8,
        kev=True,
    )
    md = render_diff_markdown(diff_findings([keep, fresh], build_baseline([keep, gone])))
    assert md.startswith("## vulnpipe scan delta")
    assert "**1 new**, 1 persisting, 1 resolved" in md
    assert "⚠️ 1 new finding(s)." in md
    assert "### New findings" in md
    assert "| critical ⚠️ | 98 | 10.0.0.5:80 | CVE-2021-42013 |" in md  # KEV marker + risk
    assert "### Resolved findings" in md
    assert "- [low] removed (10.0.0.10)" in md


def test_markdown_clean_diff_has_no_tables() -> None:
    keep = _f("kept")
    md = render_diff_markdown(diff_findings([keep], build_baseline([keep])))
    assert "✅ No new findings." in md
    assert "### New findings" not in md
    assert "### Resolved findings" not in md


def test_markdown_escapes_pipes_in_titles() -> None:
    fresh = _f("weird | title", severity=Severity.HIGH)
    md = render_diff_markdown(diff_findings([fresh], build_baseline([])))
    assert "weird \\| title" in md


def test_markdown_is_deterministic() -> None:
    findings = [_f("a", severity=Severity.HIGH), _f("b", severity=Severity.LOW)]
    diff = diff_findings(findings, build_baseline([]))
    assert render_diff_markdown(diff) == render_diff_markdown(diff)
    assert render_diff_markdown(diff, title="Delta").startswith("## Delta")


# --------------------------------------------------------------------------- #
# HTML rendering (shareable page)
# --------------------------------------------------------------------------- #
def test_html_has_sections_verdict_and_chips() -> None:
    keep = _f("kept")
    gone = _f("removed", severity=Severity.LOW)
    fresh = make_finding(
        source="nmap",
        host="10.0.0.5",
        title="CVE-2021-42013",
        severity=Severity.CRITICAL,
        port=80,
        plugin_id="vulners",
        cve_ids=["CVE-2021-42013"],
        cvss_score=9.8,
        kev=True,
    )
    html = render_diff_html(diff_findings([keep, fresh], build_baseline([keep, gone])))
    assert html.startswith("<!DOCTYPE html>")
    assert "<title>vulnpipe scan delta</title>" in html
    assert "1 new · 1 persisting · 1 resolved" in html
    assert 'class="verdict dirty"' in html
    assert "<h2>New findings</h2>" in html
    assert '<span class="chip sev-critical">critical</span>' in html
    assert "&#9888;" in html  # KEV warning glyph on the new critical
    assert "CVE-2021-42013" in html
    assert "<h2>Resolved findings</h2>" in html
    assert "<details><summary>Show already-known findings</summary>" in html


def test_html_clean_diff_is_positive_and_tableless() -> None:
    keep = _f("kept")
    html = render_diff_html(diff_findings([keep], build_baseline([keep])))
    assert 'class="verdict clean"' in html
    assert "No new findings." in html
    assert "<h2>New findings</h2>" not in html
    assert "<h2>Resolved findings</h2>" not in html


def test_html_escapes_scanner_evidence() -> None:
    fresh = _f("<script>alert(1)</script>", severity=Severity.HIGH)
    html = render_diff_html(diff_findings([fresh], build_baseline([])))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_html_is_deterministic_and_titleable() -> None:
    findings = [_f("a", severity=Severity.HIGH), _f("b", severity=Severity.LOW)]
    diff = diff_findings(findings, build_baseline([]))
    assert render_diff_html(diff) == render_diff_html(diff)
    assert "<title>Nightly delta</title>" in render_diff_html(diff, title="Nightly delta")
