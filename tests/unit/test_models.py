"""Unit tests for the core data models."""

import pytest
from pydantic import ValidationError

from vulnpipe.core.models import (
    AssetCriticality,
    Confidence,
    Finding,
    Host,
    Service,
    Severity,
    compute_fingerprint,
    normalize_title,
)


def test_severity_rank_ordering() -> None:
    assert Severity.INFORMATIONAL.rank < Severity.LOW.rank < Severity.MEDIUM.rank
    assert Severity.MEDIUM.rank < Severity.HIGH.rank < Severity.CRITICAL.rank


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, Severity.INFORMATIONAL),
        (0.1, Severity.LOW),
        (3.9, Severity.LOW),
        (4.0, Severity.MEDIUM),
        (6.9, Severity.MEDIUM),
        (7.0, Severity.HIGH),
        (8.9, Severity.HIGH),
        (9.0, Severity.CRITICAL),
        (10.0, Severity.CRITICAL),
    ],
)
def test_from_cvss_score(score: float, expected: Severity) -> None:
    assert Severity.from_cvss_score(score) is expected


@pytest.mark.parametrize("score", [-0.1, 10.1])
def test_from_cvss_score_out_of_range(score: float) -> None:
    with pytest.raises(ValueError):
        Severity.from_cvss_score(score)


def test_confidence_rank_ordering() -> None:
    assert Confidence.FALSE_POSITIVE.rank < Confidence.LOW.rank
    assert Confidence.HIGH.rank < Confidence.CONFIRMED.rank


def test_asset_criticality_rank_ordering() -> None:
    assert AssetCriticality.LOW.rank < AssetCriticality.MEDIUM.rank
    assert AssetCriticality.MEDIUM.rank < AssetCriticality.HIGH.rank
    assert AssetCriticality.HIGH.rank < AssetCriticality.CRITICAL.rank


def test_normalize_title_collapses_and_lowercases() -> None:
    assert normalize_title("  SQL   Injection\t") == "sql injection"


def test_service_validates_port_and_protocol() -> None:
    svc = Service(port=443, protocol="TCP", name="https")
    assert svc.protocol == "tcp"
    with pytest.raises(ValidationError):
        Service(port=70000)
    with pytest.raises(ValidationError):
        Service(port=80, protocol="carrier-pigeon")


def test_host_holds_services() -> None:
    host = Host(address="10.0.0.5", services=(Service(port=22, name="ssh"),))
    assert host.services[0].port == 22


def test_finding_fingerprint_is_deterministic_and_title_normalized() -> None:
    f1 = Finding(source="zap", host="10.0.0.5", port=443, plugin_id="40012", title="SQL Injection")
    f2 = Finding(
        source="zap", host="10.0.0.5", port=443, plugin_id="40012", title="  sql   injection "
    )
    assert f1.fingerprint == f2.fingerprint
    assert f1.fingerprint == compute_fingerprint(
        host="10.0.0.5", port=443, source="zap", plugin_or_alert_id="40012", title="SQL Injection"
    )


def test_finding_fingerprint_changes_with_identity_fields() -> None:
    base = Finding(source="zap", host="10.0.0.5", port=443, plugin_id="1", title="X")
    assert base.fingerprint != base.model_copy(update={"host": "10.0.0.6"}).fingerprint
    assert base.fingerprint != base.model_copy(update={"port": 8443}).fingerprint
    assert base.fingerprint != base.model_copy(update={"title": "Y"}).fingerprint


def test_finding_fingerprint_stable_across_enrichment() -> None:
    finding = Finding(source="nmap", host="10.0.0.5", port=443, plugin_id="v", title="CVE issue")
    enriched = finding.model_copy(update={"cvss_score": 9.8, "severity": Severity.CRITICAL})
    assert enriched.fingerprint == finding.fingerprint
    assert enriched.cvss_score == 9.8


def test_finding_is_frozen() -> None:
    finding = Finding(source="nmap", host="10.0.0.5", title="X")
    with pytest.raises((ValidationError, TypeError)):
        finding.severity = Severity.HIGH


def test_finding_rejects_out_of_range_scores() -> None:
    with pytest.raises(ValidationError):
        Finding(source="nmap", host="10.0.0.5", title="X", cvss_score=11.0)
    with pytest.raises(ValidationError):
        Finding(source="nmap", host="10.0.0.5", title="X", epss_score=2.0)
