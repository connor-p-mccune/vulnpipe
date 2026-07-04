"""Unit tests for the GitLab security report reporter.

Cover the document shape, severity mapping, identifiers (CVE / CWE / vulnpipe rule),
the DAST location, deterministic snapshot output, and the reproducible scan
timestamp (SOURCE_DATE_EPOCH).
"""

import json

import pytest

from vulnpipe.core.models import Confidence, Finding, Severity
from vulnpipe.processing.normalizer import make_finding
from vulnpipe.reporting import get_reporter
from vulnpipe.reporting.gitlab_reporter import (
    GITLAB_SCHEMA_VERSION,
    GitlabReporter,
    build_gitlab_report,
    render_gitlab,
)


def _findings() -> list[Finding]:
    return [
        make_finding(
            source="nmap",
            host="10.0.0.5",
            title="CVE-2021-42013",
            severity=Severity.CRITICAL,
            port=80,
            plugin_id="vulners",
            cve_ids=["CVE-2021-42013"],
            cvss_score=9.8,
            kev=True,
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-42013"],
            metadata={"product": "Apache httpd", "version": "2.4.49", "service": "http"},
        ),
        make_finding(
            source="zap",
            host="app.lab.example.com",
            title="Cross Site Scripting (Reflected)",
            severity=Severity.HIGH,
            port=443,
            plugin_id="40012",
            confidence=Confidence.MEDIUM,
            description="Reflected input is rendered without encoding.",
            solution="Encode output.",
            cwe_ids=["CWE-79"],
            metadata={
                "url": "https://app.lab.example.com/search?q=1",
                "method": "GET",
                "param": "q",
            },
        ),
    ]


def test_document_envelope() -> None:
    report = build_gitlab_report(_findings())
    assert report["version"] == GITLAB_SCHEMA_VERSION
    assert report["scan"]["type"] == "dast"
    assert report["scan"]["status"] == "success"
    assert report["scan"]["scanner"]["id"] == "vulnpipe"
    assert len(report["vulnerabilities"]) == 2


def test_pure_build_omits_scan_times() -> None:
    scan = build_gitlab_report(_findings())["scan"]
    assert "start_time" not in scan and "end_time" not in scan


def test_severity_maps_to_gitlab_vocabulary() -> None:
    report = build_gitlab_report(_findings())
    severities = [vuln["severity"] for vuln in report["vulnerabilities"]]
    assert severities == ["Critical", "High"]


def test_informational_maps_to_info() -> None:
    finding = make_finding(source="nmap", host="10.0.0.5", title="Open port 22/tcp")
    report = build_gitlab_report([finding])
    assert report["vulnerabilities"][0]["severity"] == "Info"


def test_vulnerability_id_is_the_fingerprint() -> None:
    findings = _findings()
    report = build_gitlab_report(findings)
    assert report["vulnerabilities"][0]["id"] == findings[0].fingerprint


def test_identifiers_carry_cve_cwe_and_rule() -> None:
    report = build_gitlab_report(_findings())
    cve_vuln = report["vulnerabilities"][0]
    types = [ident["type"] for ident in cve_vuln["identifiers"]]
    assert types[0] == "cve"  # CVE leads so it is primary
    assert types[-1] == "vulnpipe_rule"  # a rule id is always present
    cve = cve_vuln["identifiers"][0]
    assert cve["value"] == "CVE-2021-42013"
    assert cve["url"].endswith("/CVE-2021-42013")

    xss_vuln = report["vulnerabilities"][1]
    cwe = next(ident for ident in xss_vuln["identifiers"] if ident["type"] == "cwe")
    assert cwe["name"] == "CWE-79"
    assert cwe["value"] == "79"
    assert cwe["url"] == "https://cwe.mitre.org/data/definitions/79.html"


def test_every_vulnerability_has_at_least_one_identifier() -> None:
    finding = make_finding(source="nmap", host="10.0.0.5", title="Open port 22/tcp")
    report = build_gitlab_report([finding])
    identifiers = report["vulnerabilities"][0]["identifiers"]
    assert len(identifiers) == 1
    assert identifiers[0]["type"] == "vulnpipe_rule"


def test_dast_location_from_url_and_from_host() -> None:
    report = build_gitlab_report(_findings())
    network_loc = report["vulnerabilities"][0]["location"]
    assert network_loc == {"hostname": "10.0.0.5", "path": "/"}
    web_loc = report["vulnerabilities"][1]["location"]
    assert web_loc["hostname"] == "app.lab.example.com"
    assert web_loc["path"] == "/search"
    assert web_loc["method"] == "GET"
    assert web_loc["param"] == "q"


def test_description_and_solution_only_when_present() -> None:
    report = build_gitlab_report(_findings())
    assert "description" not in report["vulnerabilities"][0]  # network CVE has none
    xss = report["vulnerabilities"][1]
    assert xss["description"] == "Reflected input is rendered without encoding."
    assert xss["solution"] == "Encode output."


def test_links_are_http_only() -> None:
    finding = make_finding(
        source="zap",
        host="h",
        title="X",
        references=["https://example.com/a", "see vendor notes", "http://ref/b"],
    )
    report = build_gitlab_report([finding])
    links = report["vulnerabilities"][0]["links"]
    assert links == [{"url": "https://example.com/a"}, {"url": "http://ref/b"}]


def test_render_is_valid_json_and_deterministic() -> None:
    first = render_gitlab(_findings(), timestamp="2020-01-01T00:00:00")
    second = render_gitlab(_findings(), timestamp="2020-01-01T00:00:00")
    assert first == second
    document = json.loads(first)
    assert document["scan"]["start_time"] == "2020-01-01T00:00:00"
    assert document["scan"]["end_time"] == "2020-01-01T00:00:00"


def test_reporter_stamps_reproducible_time(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
    document = json.loads(GitlabReporter().render(_findings()))
    assert document["scan"]["start_time"] == "1970-01-01T00:00:00"


def test_reporter_rejects_bad_source_date_epoch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "not-a-number")
    with pytest.raises(ValueError):
        GitlabReporter().render(_findings())


def test_registered_under_gitlab_format() -> None:
    assert isinstance(get_reporter("gitlab"), GitlabReporter)


def test_reporter_name() -> None:
    assert GitlabReporter.name == "gitlab"
