"""Unit tests for deterministic finding prioritization."""

import random

from vulnpipe.core.models import AssetCriticality, Finding, Severity
from vulnpipe.processing.normalizer import make_finding
from vulnpipe.processing.prioritizer import prioritize


def _f(
    title: str,
    *,
    severity: Severity = Severity.MEDIUM,
    cvss: float | None = None,
    epss: float | None = None,
    host: str = "10.0.0.5",
) -> Finding:
    return make_finding(
        source="nmap",
        host=host,
        title=title,
        severity=severity,
        cvss_score=cvss,
        epss_score=epss,
    )


def test_orders_by_severity_descending() -> None:
    findings = [
        _f("info", severity=Severity.INFORMATIONAL),
        _f("crit", severity=Severity.CRITICAL),
        _f("low", severity=Severity.LOW),
        _f("high", severity=Severity.HIGH),
        _f("med", severity=Severity.MEDIUM),
    ]
    result = prioritize(findings)
    assert [f.severity for f in result] == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFORMATIONAL,
    ]


def test_breaks_severity_ties_by_cvss() -> None:
    result = prioritize(
        [
            _f("lower", severity=Severity.HIGH, cvss=7.1),
            _f("higher", severity=Severity.HIGH, cvss=8.9),
        ]
    )
    assert [f.title for f in result] == ["higher", "lower"]


def test_breaks_cvss_ties_by_epss() -> None:
    result = prioritize(
        [
            _f("lower", severity=Severity.HIGH, cvss=7.5, epss=0.2),
            _f("higher", severity=Severity.HIGH, cvss=7.5, epss=0.9),
        ]
    )
    assert [f.title for f in result] == ["higher", "lower"]


def test_breaks_remaining_ties_by_asset_criticality() -> None:
    def resolve(host: str) -> AssetCriticality:
        return AssetCriticality.CRITICAL if host == "crit" else AssetCriticality.LOW

    # Identical severity/CVSS/EPSS: only the affected asset's criticality differs.
    result = prioritize(
        [
            _f("a", severity=Severity.HIGH, cvss=7.5, epss=0.5, host="low"),
            _f("b", severity=Severity.HIGH, cvss=7.5, epss=0.5, host="crit"),
        ],
        criticality=resolve,
    )
    assert [f.host for f in result] == ["crit", "low"]


def test_missing_scores_sort_after_present_ones() -> None:
    result = prioritize(
        [
            _f("unscored", severity=Severity.MEDIUM, cvss=None),
            _f("scored", severity=Severity.MEDIUM, cvss=4.0),
        ]
    )
    assert [f.title for f in result] == ["scored", "unscored"]


def test_is_deterministic_regardless_of_input_order() -> None:
    findings = [
        _f("a", severity=Severity.HIGH, cvss=7.5, epss=0.5),
        _f("b", severity=Severity.CRITICAL),
        _f("c", severity=Severity.LOW, cvss=2.0),
        _f("d", severity=Severity.HIGH, cvss=9.0),
        _f("e", severity=Severity.MEDIUM, cvss=5.0, epss=0.1),
    ]
    expected = [f.fingerprint for f in prioritize(findings)]
    shuffled = list(findings)
    random.Random(1234).shuffle(shuffled)
    assert [f.fingerprint for f in prioritize(shuffled)] == expected


def test_default_criticality_is_uniform_and_stable() -> None:
    # Without a resolver, criticality cannot change the order; the stable fingerprint
    # tie-breaker decides it, so input order does not matter.
    a = _f("a", severity=Severity.HIGH, cvss=7.5, host="h1")
    b = _f("b", severity=Severity.HIGH, cvss=7.5, host="h2")
    assert [f.fingerprint for f in prioritize([a, b])] == [
        f.fingerprint for f in prioritize([b, a])
    ]


def test_does_not_mutate_input() -> None:
    findings = [_f("a", severity=Severity.LOW), _f("b", severity=Severity.HIGH)]
    snapshot = list(findings)
    prioritize(findings)
    assert findings == snapshot  # input list left untouched


def test_empty() -> None:
    assert prioritize([]) == []
