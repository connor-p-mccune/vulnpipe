"""Unit tests for baseline persistence.

Covers building a baseline from findings (deduplicated and order-independent),
the deterministic on-disk form, the save/load round-trip, union merging, and the
load-time error guards. No network or filesystem access beyond ``tmp_path``.
"""

import random
from datetime import date
from pathlib import Path

import pytest

from vulnpipe.ci.baseline import (
    BASELINE_SCHEMA_VERSION,
    Baseline,
    BaselineEntry,
    BaselineError,
    baseline_to_json,
    build_baseline,
    load_baseline,
    merge_baseline,
    save_baseline,
)
from vulnpipe.core.models import Finding, Severity
from vulnpipe.processing.normalizer import make_finding


def _f(title: str, *, host: str = "10.0.0.10", severity: Severity = Severity.HIGH) -> Finding:
    return make_finding(source="nmap", host=host, title=title, severity=severity, plugin_id="x")


def test_entry_snapshots_finding_identity() -> None:
    finding = _f("CVE-2021-44228", host="10.0.0.5", severity=Severity.CRITICAL)
    entry = BaselineEntry.from_finding(finding)
    assert entry.fingerprint == finding.fingerprint
    assert entry.source == "nmap"
    assert entry.host == "10.0.0.5"
    assert entry.title == "CVE-2021-44228"
    assert entry.severity is Severity.CRITICAL


def test_build_dedupes_and_is_order_independent() -> None:
    findings = [_f("a"), _f("b"), _f("a")]  # "a" appears twice (same fingerprint)
    baseline = build_baseline(findings)
    assert len(baseline.entries) == 2
    # Stored in fingerprint order, so shuffling the input cannot change the result.
    shuffled = list(findings)
    random.Random(7).shuffle(shuffled)
    assert build_baseline(shuffled) == baseline


def test_fingerprints_and_entry_for() -> None:
    a, b = _f("a"), _f("b")
    baseline = build_baseline([a, b])
    assert baseline.fingerprints == {a.fingerprint, b.fingerprint}
    assert baseline.entry_for(a.fingerprint) is not None
    assert baseline.entry_for("does-not-exist") is None


def test_save_load_round_trips(tmp_path: Path) -> None:
    baseline = build_baseline([_f("a"), _f("b", host="10.0.0.11")])
    path = tmp_path / "baseline.json"
    save_baseline(baseline, path)
    assert load_baseline(path) == baseline


def test_save_creates_parent_dirs(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "dir" / "baseline.json"
    save_baseline(build_baseline([_f("a")]), path)
    assert path.is_file()


def test_serialization_is_deterministic_without_timestamp() -> None:
    findings = [_f("a"), _f("b"), _f("c")]
    first = baseline_to_json(build_baseline(findings))
    shuffled = list(findings)
    random.Random(99).shuffle(shuffled)
    assert baseline_to_json(build_baseline(shuffled)) == first
    assert BASELINE_SCHEMA_VERSION in first


def test_merge_unions_and_preserves_existing(tmp_path: Path) -> None:
    original = build_baseline([_f("a")])
    merged = merge_baseline(original, [_f("a"), _f("b")])
    assert merged.fingerprints == {_f("a").fingerprint, _f("b").fingerprint}
    # The pre-existing entry's snapshot is kept, not replaced by the new sighting.
    assert merged.entry_for(_f("a").fingerprint) == original.entry_for(_f("a").fingerprint)


def test_load_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(BaselineError, match="not found"):
        load_baseline(tmp_path / "missing.json")


def test_load_invalid_json_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    with pytest.raises(BaselineError):
        load_baseline(bad)


def test_load_non_mapping_root_raises(tmp_path: Path) -> None:
    arr = tmp_path / "arr.json"
    arr.write_text("[]", encoding="utf-8")
    with pytest.raises(BaselineError, match="mapping"):
        load_baseline(arr)


def test_load_invalid_schema_raises(tmp_path: Path) -> None:
    bad = tmp_path / "schema.json"
    bad.write_text('{"entries": [{"fingerprint": "x"}]}', encoding="utf-8")  # missing fields
    with pytest.raises(BaselineError, match="Invalid baseline"):
        load_baseline(bad)


def test_empty_baseline_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "empty.json"
    save_baseline(Baseline(), path)
    loaded = load_baseline(path)
    assert loaded.entries == ()
    assert loaded.fingerprints == frozenset()


# --------------------------------------------------------------------------- #
# first_seen / age tracking
# --------------------------------------------------------------------------- #
def test_first_seen_defaults_none_and_stamps_when_given() -> None:
    plain = build_baseline([_f("a")])
    assert plain.entries[0].first_seen is None
    stamped = build_baseline([_f("a")], first_seen=date(2026, 1, 1))
    assert stamped.entries[0].first_seen == date(2026, 1, 1)
    assert stamped.first_seen(_f("a").fingerprint) == date(2026, 1, 1)


def test_first_seen_omitted_from_json_when_unset() -> None:
    assert "first_seen" not in baseline_to_json(build_baseline([_f("a")]))


def test_first_seen_present_in_json_and_round_trips(tmp_path: Path) -> None:
    baseline = build_baseline([_f("a")], first_seen=date(2026, 1, 1))
    text = baseline_to_json(baseline)
    assert '"first_seen": "2026-01-01"' in text
    path = tmp_path / "b.json"
    save_baseline(baseline, path)
    assert load_baseline(path) == baseline


def test_merge_preserves_original_first_seen() -> None:
    original = build_baseline([_f("a")], first_seen=date(2026, 1, 1))
    merged = merge_baseline(original, [_f("a"), _f("b")], first_seen=date(2026, 6, 1))
    # The pre-existing finding keeps its original date; the new one takes the later one.
    assert merged.first_seen(_f("a").fingerprint) == date(2026, 1, 1)
    assert merged.first_seen(_f("b").fingerprint) == date(2026, 6, 1)
