"""Unit tests for the SARIF 2.1.0 reporter.

Asserts the document is structurally valid SARIF (the shape GitHub code scanning
expects), is deterministic for fixed input, and maps vulnpipe severity, CVSS, CWE,
and fingerprints onto the right SARIF fields.
"""

import json

from vulnpipe.core.models import Confidence, Finding, Severity
from vulnpipe.processing.normalizer import make_finding
from vulnpipe.reporting.sarif_reporter import (
    SARIF_VERSION,
    SarifReporter,
    build_sarif,
)

_VALID_LEVELS = {"error", "warning", "note", "none"}


def _findings() -> list[Finding]:
    return [
        make_finding(
            source="nmap",
            host="10.0.0.10",
            title="OpenSSL vulnerability",
            severity=Severity.CRITICAL,
            port=443,
            plugin_id="vulners",
            cve_ids=["CVE-2021-44228"],
            cwe_ids=["CWE-502"],
            cvss_score=9.8,
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        ),
        make_finding(
            source="zap",
            host="app.lab.example.com",
            title="Cross Site Scripting (Reflected)",
            severity=Severity.HIGH,
            port=443,
            plugin_id="40012",
            confidence=Confidence.MEDIUM,
            cwe_ids=["CWE-79"],
            solution="Encode output.",
            metadata={"url": "https://app.lab.example.com/search?q=test"},
        ),
        make_finding(
            source="zap",
            host="app.lab.example.com",
            title="Timestamp Disclosure - Unix",
            severity=Severity.INFORMATIONAL,
            plugin_id="10096",
        ),
    ]


def _document() -> dict[str, object]:
    return build_sarif(_findings())


def test_top_level_shape() -> None:
    doc = _document()
    assert doc["version"] == SARIF_VERSION
    assert "$schema" in doc
    runs = doc["runs"]
    assert isinstance(runs, list) and len(runs) == 1
    driver = runs[0]["tool"]["driver"]
    assert driver["name"] == "vulnpipe"
    assert driver["version"] == driver["semanticVersion"]


def test_every_result_references_an_existing_rule() -> None:
    run = _document()["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    rule_ids = [rule["id"] for rule in rules]
    for result in run["results"]:
        assert result["ruleId"] in rule_ids
        # ruleIndex must point at the rule with that id.
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_results_are_valid_and_carry_fingerprints() -> None:
    original = _findings()
    results = _document()["runs"][0]["results"]
    assert len(results) == len(original)
    for finding, result in zip(original, results, strict=True):
        assert result["level"] in _VALID_LEVELS
        assert result["partialFingerprints"]["vulnpipeFingerprint/v1"] == finding.fingerprint
        assert result["message"]["text"].startswith(finding.title)


def test_severity_maps_to_level() -> None:
    by_rule = {r["ruleId"]: r for r in _document()["runs"][0]["results"]}
    assert by_rule["nmap/vulners"]["level"] == "error"  # critical -> error
    assert by_rule["zap/40012"]["level"] == "error"  # high -> error
    assert by_rule["zap/10096"]["level"] == "none"  # informational -> none


def test_security_severity_prefers_real_cvss_then_band_floor() -> None:
    rules = {r["id"]: r for r in _document()["runs"][0]["tool"]["driver"]["rules"]}
    # Real CVSS score is reported verbatim.
    assert rules["nmap/vulners"]["properties"]["security-severity"] == "9.8"
    # No CVSS: the High band floor (7.0) is used as the dashboard ranking hint.
    assert rules["zap/40012"]["properties"]["security-severity"] == "7.0"


def test_rule_tags_include_security_marker_and_cwes() -> None:
    rules = {r["id"]: r for r in _document()["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["zap/40012"]["properties"]["tags"] == ["security", "external/cwe/CWE-79"]


def test_locations_use_url_then_host_port() -> None:
    by_rule = {r["ruleId"]: r for r in _document()["runs"][0]["results"]}
    xss_loc = by_rule["zap/40012"]["locations"][0]
    assert xss_loc["physicalLocation"]["artifactLocation"]["uri"].startswith("https://")
    net_loc = by_rule["nmap/vulners"]["locations"][0]
    assert net_loc["physicalLocation"]["artifactLocation"]["uri"] == "10.0.0.10:443"
    assert net_loc["logicalLocations"][0]["fullyQualifiedName"] == "10.0.0.10:443"


def test_duplicate_rule_keeps_worst_case_security_severity() -> None:
    findings = [
        make_finding(source="zap", host="a.example.com", title="XSS", plugin_id="40012"),
        make_finding(
            source="zap", host="b.example.com", title="XSS", plugin_id="40012", cvss_score=8.1
        ),
    ]
    rules = build_sarif(findings)["runs"][0]["tool"]["driver"]["rules"]
    # One shared rule, ranked by the worst (highest) security-severity in the group.
    assert len(rules) == 1
    assert rules[0]["properties"]["security-severity"] == "8.1"


def test_render_is_deterministic_and_valid_json() -> None:
    reporter = SarifReporter()
    first = reporter.render(_findings())
    assert first == reporter.render(_findings())
    assert json.loads(first)["version"] == SARIF_VERSION


def test_rule_id_slugs_title_when_no_plugin_id() -> None:
    findings = [
        make_finding(source="nmap", host="h", title="Weak TLS Configuration"),
        make_finding(source="nmap", host="h2", title="!!!"),
    ]
    rule_ids = [r["ruleId"] for r in build_sarif(findings)["runs"][0]["results"]]
    assert rule_ids[0] == "nmap/weak-tls-configuration"
    assert rule_ids[1] == "nmap/finding"  # unsluggable title falls back


def test_optional_description_and_epss_are_emitted() -> None:
    finding = make_finding(
        source="nmap",
        host="10.0.0.1",
        title="Heartbleed",
        plugin_id="vulners",
        description="Memory disclosure in OpenSSL.",
        cvss_score=7.5,
        epss_score=0.6,
    )
    run = build_sarif([finding])["runs"][0]
    assert run["tool"]["driver"]["rules"][0]["fullDescription"]["text"].startswith("Memory")
    assert run["results"][0]["properties"]["epssScore"] == 0.6


def test_result_carries_risk_score_and_kev() -> None:
    finding = make_finding(
        source="nmap",
        host="10.0.0.5",
        title="CVE-2021-42013",
        plugin_id="vulners",
        cve_ids=["CVE-2021-42013"],
        cvss_score=9.8,
        kev=True,
    )
    props = build_sarif([finding])["runs"][0]["results"][0]["properties"]
    assert props["riskScore"] == finding.risk_score
    assert props["kev"] is True


def test_result_omits_kev_when_not_known_exploited() -> None:
    finding = make_finding(source="zap", host="h", title="X", plugin_id="1")
    props = build_sarif([finding])["runs"][0]["results"][0]["properties"]
    assert "kev" not in props  # only emitted when true
    assert props["riskScore"] == finding.risk_score  # always present


def test_duplicate_rule_keeps_higher_security_severity_when_later_is_lower() -> None:
    findings = [
        make_finding(source="zap", host="a", title="X", plugin_id="1", cvss_score=9.0),
        make_finding(source="zap", host="b", title="X", plugin_id="1", cvss_score=5.0),
    ]
    rules = build_sarif(findings)["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["properties"]["security-severity"] == "9.0"  # not lowered


def test_empty_findings_produce_valid_empty_run() -> None:
    doc = build_sarif([])
    run = doc["runs"][0]
    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []
