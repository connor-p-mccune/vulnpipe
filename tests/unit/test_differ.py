"""Unit tests for baseline-vs-current diffing.

Drives a synthetic baseline-vs-current pair and asserts each finding lands in the
right bucket (new / persisting / resolved), that ordering is deterministic, and
that the serialized payload is stable.
"""

import random

from vulnpipe.ci.baseline import build_baseline
from vulnpipe.ci.differ import Diff, diff_findings, diff_to_payload
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
