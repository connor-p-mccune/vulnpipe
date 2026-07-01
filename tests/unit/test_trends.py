"""Unit tests for multi-scan trend analysis (pure functions, deterministic)."""

from vulnpipe.ci.trends import (
    Snapshot,
    build_trend,
    render_trend_text,
    trend_to_payload,
)
from vulnpipe.core.models import Finding, Severity
from vulnpipe.processing.normalizer import make_finding


def _f(title: str, *, severity: Severity = Severity.MEDIUM, kev: bool = False) -> Finding:
    return make_finding(source="nmap", host="10.0.0.5", title=title, severity=severity, kev=kev)


def _snapshots() -> list[Snapshot]:
    scan_a = [
        _f("CVE-2021-42013", severity=Severity.CRITICAL, kev=True),
        _f("CVE-2016-10009", severity=Severity.HIGH),
        _f("Open port 22/tcp", severity=Severity.INFORMATIONAL),
    ]
    scan_b = [
        _f("CVE-2021-42013", severity=Severity.CRITICAL, kev=True),  # persists
        _f("CVE-2016-10009", severity=Severity.HIGH),  # persists
        _f("CVE-2021-23017", severity=Severity.HIGH),  # introduced
        # the informational finding resolved
    ]
    return [("2026-06-01", scan_a), ("2026-06-15", scan_b)]


def test_first_scan_counts_everything_introduced() -> None:
    trend = build_trend(_snapshots())
    first = trend.points[0]
    assert first.total == 3
    assert first.introduced == 3  # everything is new on the first scan
    assert first.resolved == 0
    assert first.kev == 1
    assert first.serious == 2  # 1 critical + 1 high


def test_deltas_between_consecutive_scans() -> None:
    trend = build_trend(_snapshots())
    second = trend.points[1]
    assert second.total == 3
    assert second.introduced == 1  # CVE-2021-23017 is new
    assert second.resolved == 1  # the informational finding disappeared
    assert second.serious == 3  # 1 critical + 2 high


def test_direction_worsening_and_net_change() -> None:
    trend = build_trend(_snapshots())
    assert trend.direction == "worsening"  # serious backlog 2 -> 3
    assert trend.net_serious_change == 1


def test_direction_improving() -> None:
    worse = [_f("a", severity=Severity.HIGH), _f("b", severity=Severity.HIGH)]
    better = [_f("a", severity=Severity.HIGH)]
    trend = build_trend([("t0", worse), ("t1", better)])
    assert trend.direction == "improving"
    assert trend.net_serious_change == -1


def test_direction_flat_for_single_scan() -> None:
    trend = build_trend([("only", [_f("a", severity=Severity.HIGH)])])
    assert trend.direction == "flat"
    assert trend.net_serious_change == 0


def test_direction_flat_for_unchanged_backlog() -> None:
    # Two scans, same critical+high count (churn but no net change) -> flat.
    scan_a = [_f("a", severity=Severity.HIGH)]
    scan_b = [_f("b", severity=Severity.HIGH)]
    trend = build_trend([("t0", scan_a), ("t1", scan_b)])
    assert trend.direction == "flat"
    assert trend.net_serious_change == 0


def test_empty_series() -> None:
    trend = build_trend([])
    assert trend.points == ()
    assert trend.direction == "flat"
    assert trend.net_serious_change == 0


def test_trend_to_payload_shape() -> None:
    payload = trend_to_payload(build_trend(_snapshots()))
    assert payload["direction"] == "worsening"
    assert payload["net_serious_change"] == 1
    assert [scan["label"] for scan in payload["scans"]] == ["2026-06-01", "2026-06-15"]
    assert payload["scans"][1]["introduced"] == 1
    assert payload["scans"][1]["by_severity"]["high"] == 2
    assert payload["scans"][0]["kev"] == 1


def test_render_text_table_and_summary() -> None:
    text = render_trend_text(build_trend(_snapshots()))
    assert "scan" in text and "total" in text and "+new" in text
    assert "2026-06-01" in text and "2026-06-15" in text
    assert "risk trend: worsening" in text
    assert text.endswith("\n")


def test_render_is_deterministic() -> None:
    snaps = _snapshots()
    assert render_trend_text(build_trend(snaps)) == render_trend_text(build_trend(snaps))
