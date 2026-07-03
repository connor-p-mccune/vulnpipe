"""Unit tests for false-positive suppression and allowlist loading."""

from datetime import date
from pathlib import Path
from typing import Any

import pytest

from vulnpipe.core.models import Confidence, Finding
from vulnpipe.processing.false_positive import (
    FalsePositiveConfig,
    FingerprintRule,
    HostRule,
    PluginRule,
    expired_entries,
    filter_false_positives,
    is_false_positive,
    load_false_positive_config,
)
from vulnpipe.processing.normalizer import make_finding

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_ALLOWLIST = REPO_ROOT / "configs" / "false_positives.example.yaml"


def _finding(**overrides: Any) -> Finding:
    params: dict[str, Any] = {"source": "zap", "host": "10.0.0.10", "title": "Issue", "port": 443}
    params.update(overrides)
    return make_finding(**params)


def test_suppress_by_fingerprint() -> None:
    finding = _finding(plugin_id="40012")
    allowlist = FalsePositiveConfig(fingerprints=(finding.fingerprint,))
    assert is_false_positive(finding, allowlist) is True
    assert is_false_positive(_finding(plugin_id="99999"), allowlist) is False


def test_suppress_by_host() -> None:
    allowlist = FalsePositiveConfig(hosts=("10.0.0.10",))
    assert is_false_positive(_finding(host="10.0.0.10"), allowlist) is True
    assert is_false_positive(_finding(host="10.0.0.11"), allowlist) is False


def test_suppress_by_plugin_id() -> None:
    allowlist = FalsePositiveConfig(plugins=(PluginRule(id="10096"),))
    assert is_false_positive(_finding(plugin_id="10096"), allowlist) is True
    assert is_false_positive(_finding(plugin_id="10097"), allowlist) is False
    assert is_false_positive(_finding(plugin_id=None), allowlist) is False


def test_plugin_rule_can_be_scoped_to_a_host() -> None:
    allowlist = FalsePositiveConfig(plugins=(PluginRule(id="10096", host="10.0.0.10"),))
    assert is_false_positive(_finding(host="10.0.0.10", plugin_id="10096"), allowlist) is True
    # Same plugin on a different host is not suppressed by a host-pinned rule.
    assert is_false_positive(_finding(host="10.0.0.99", plugin_id="10096"), allowlist) is False


def test_min_confidence_drops_below_threshold() -> None:
    allowlist = FalsePositiveConfig(min_confidence=Confidence.MEDIUM)
    assert is_false_positive(_finding(confidence=Confidence.LOW), allowlist) is True
    assert is_false_positive(_finding(confidence=Confidence.MEDIUM), allowlist) is False
    assert is_false_positive(_finding(confidence=Confidence.HIGH), allowlist) is False
    # No confidence signal (e.g. Nmap) is not "low confidence" -> kept.
    assert is_false_positive(_finding(confidence=None), allowlist) is False


def test_empty_allowlist_suppresses_nothing() -> None:
    allowlist = FalsePositiveConfig()
    findings = [_finding(plugin_id="1"), _finding(confidence=Confidence.LOW)]
    assert filter_false_positives(findings, allowlist) == findings


def test_filter_preserves_order_and_drops_only_matches() -> None:
    keep_a = _finding(host="10.0.0.10", plugin_id="1")
    drop = _finding(host="10.0.0.10", plugin_id="10096")
    keep_b = _finding(host="10.0.0.10", plugin_id="2")
    allowlist = FalsePositiveConfig(plugins=(PluginRule(id="10096"),))
    result = filter_false_positives([keep_a, drop, keep_b], allowlist)
    assert result == [keep_a, keep_b]


def test_load_example_allowlist() -> None:
    allowlist = load_false_positive_config(EXAMPLE_ALLOWLIST)
    assert allowlist.min_confidence is Confidence.LOW
    assert allowlist.fingerprints == (
        FingerprintRule(fingerprint="0" * 64),
        FingerprintRule(
            fingerprint="1" * 64,
            reason="Self-signed TLS certificate on the lab gateway is by design.",
            expires=date(2027, 1, 31),
        ),
    )
    assert allowlist.plugins == (
        PluginRule(
            id="10096",
            host="10.0.0.10",
            reason="Build metadata timestamps on the static marketing page.",
            expires=date(2026, 12, 31),
        ),
    )
    assert allowlist.hosts == ()


def test_load_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_false_positive_config(tmp_path / "nope.yaml")


def test_load_empty_file_is_empty_allowlist(tmp_path: Path) -> None:
    path = tmp_path / "empty.yaml"
    path.write_text("", encoding="utf-8")
    allowlist = load_false_positive_config(path)
    assert allowlist == FalsePositiveConfig()


def test_load_rejects_non_mapping_root(tmp_path: Path) -> None:
    path = tmp_path / "list.yaml"
    path.write_text("- not\n- a mapping\n", encoding="utf-8")
    with pytest.raises(ValueError, match="must be a mapping"):
        load_false_positive_config(path)


# --------------------------------------------------------------------------- #
# Time-boxed acceptances (reason + expires)
# --------------------------------------------------------------------------- #
def test_expiry_is_inclusive_of_the_expires_date() -> None:
    finding = _finding(plugin_id="40012")
    allowlist = FalsePositiveConfig(
        fingerprints=(FingerprintRule(fingerprint=finding.fingerprint, expires=date(2026, 6, 30)),)
    )
    assert is_false_positive(finding, allowlist, today=date(2026, 6, 30)) is True
    assert is_false_positive(finding, allowlist, today=date(2026, 7, 1)) is False


def test_expired_plugin_and_host_rules_stop_suppressing() -> None:
    finding = _finding(host="10.0.0.10", plugin_id="10096")
    allowlist = FalsePositiveConfig(
        plugins=(PluginRule(id="10096", expires=date(2026, 1, 1)),),
        hosts=(HostRule(host="10.0.0.10", expires=date(2026, 1, 1)),),
    )
    assert is_false_positive(finding, allowlist, today=date(2025, 12, 31)) is True
    assert is_false_positive(finding, allowlist, today=date(2026, 1, 2)) is False


def test_entries_without_expiry_suppress_indefinitely() -> None:
    finding = _finding(host="10.0.0.10")
    allowlist = FalsePositiveConfig(hosts=("10.0.0.10",))
    assert is_false_positive(finding, allowlist, today=date(2099, 1, 1)) is True


def test_filter_respects_the_pinned_evaluation_date() -> None:
    finding = _finding(plugin_id="10096")
    allowlist = FalsePositiveConfig(plugins=(PluginRule(id="10096", expires=date(2026, 3, 1)),))
    assert filter_false_positives([finding], allowlist, today=date(2026, 2, 1)) == []
    assert filter_false_positives([finding], allowlist, today=date(2026, 4, 1)) == [finding]


def test_expired_entries_lists_lapsed_rules_with_reasons() -> None:
    allowlist = FalsePositiveConfig(
        fingerprints=(
            FingerprintRule(
                fingerprint="a" * 64, reason="lab cert by design", expires=date(2026, 1, 31)
            ),
        ),
        plugins=(PluginRule(id="10096", host="10.0.0.10", expires=date(2026, 2, 28)),),
        hosts=(HostRule(host="10.0.0.99", expires=date(2099, 1, 1)),),  # still active
    )
    labels = expired_entries(allowlist, today=date(2026, 3, 1))
    assert labels == (
        "fingerprint aaaaaaaaaaaa... (expired 2026-01-31; reason: lab cert by design)",
        "plugin 10096 on 10.0.0.10 (expired 2026-02-28)",
    )


def test_expired_entries_ignores_dateless_and_active_rules() -> None:
    allowlist = FalsePositiveConfig(
        fingerprints=("b" * 64,),
        hosts=(HostRule(host="10.0.0.10", expires=date(2026, 12, 31)),),
    )
    assert expired_entries(allowlist, today=date(2026, 6, 1)) == ()


def test_load_time_boxed_entries_from_yaml(tmp_path: Path) -> None:
    path = tmp_path / "fp.yaml"
    path.write_text(
        "fingerprints:\n"
        f'  - "{"c" * 64}"\n'
        f"  - fingerprint: \"{'d' * 64}\"\n"
        '    reason: "accepted for the quarter"\n'
        "    expires: 2026-09-30\n"
        "hosts:\n"
        '  - "10.0.0.50"\n'
        '  - host: "10.0.0.51"\n'
        '    expires: "2026-09-30"\n',  # quoted string dates parse too
        encoding="utf-8",
    )
    allowlist = load_false_positive_config(path)
    assert allowlist.fingerprints[0] == FingerprintRule(fingerprint="c" * 64)
    assert allowlist.fingerprints[1].expires == date(2026, 9, 30)
    assert allowlist.fingerprints[1].reason == "accepted for the quarter"
    assert allowlist.hosts[0] == HostRule(host="10.0.0.50")
    assert allowlist.hosts[1].expires == date(2026, 9, 30)


def test_confidence_floor_never_expires() -> None:
    allowlist = FalsePositiveConfig(min_confidence=Confidence.MEDIUM)
    finding = _finding(confidence=Confidence.LOW)
    assert is_false_positive(finding, allowlist, today=date(2099, 1, 1)) is True
