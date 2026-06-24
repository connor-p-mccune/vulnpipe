"""Unit tests for false-positive suppression and allowlist loading."""

from pathlib import Path
from typing import Any

import pytest

from vulnpipe.core.models import Confidence, Finding
from vulnpipe.processing.false_positive import (
    FalsePositiveConfig,
    PluginRule,
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
    assert allowlist.fingerprints == ("0" * 64,)
    assert allowlist.plugins == (PluginRule(id="10096", host="10.0.0.10"),)
    assert allowlist.hosts == ()


def test_load_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_false_positive_config(tmp_path / "nope.yaml")


def test_load_empty_file_is_empty_allowlist(tmp_path: Path) -> None:
    path = tmp_path / "empty.yaml"
    path.write_text("", encoding="utf-8")
    allowlist = load_false_positive_config(path)
    assert allowlist == FalsePositiveConfig()
