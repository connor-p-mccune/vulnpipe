"""Unit tests for remediation planning.

Cover the three grouping kinds (package / service / class), the impact-first
ranking, the aggregate properties, honest instruction text (scanner solution vs.
template fallback), the text / Markdown / JSON renders, and determinism.
"""

from vulnpipe.core.models import Finding, Severity
from vulnpipe.processing.normalizer import make_finding
from vulnpipe.reporting.remediation import (
    RemediationAction,
    plan_remediations,
    remediation_to_payload,
    render_remediation_markdown,
    render_remediation_text,
)


def _nmap_cve(
    cve: str,
    *,
    host: str = "10.0.0.5",
    product: str = "Apache httpd",
    version: str | None = "2.4.49",
    severity: Severity = Severity.HIGH,
    cvss: float | None = 7.5,
    kev: bool = False,
) -> Finding:
    return make_finding(
        source="nmap",
        host=host,
        title=cve,
        severity=severity,
        port=80,
        plugin_id="vulners",
        cve_ids=[cve],
        cvss_score=cvss,
        kev=kev,
        metadata={"product": product, "version": version, "service": "http"},
    )


def _sbom(osv_id: str, *, package: str = "lodash", solution: str | None = None) -> Finding:
    return make_finding(
        source="sbom",
        host="my-app",
        title=f"{osv_id}: {package}@1.0.0",
        severity=Severity.MEDIUM,
        plugin_id=osv_id,
        solution=solution,
        metadata={"package": package, "package_version": "1.0.0"},
    )


def _zap(title: str, *, host: str = "app.example.com", solution: str | None = None) -> Finding:
    return make_finding(
        source="zap",
        host=host,
        title=title,
        severity=Severity.HIGH,
        port=443,
        plugin_id="40012",
        solution=solution,
    )


# --------------------------------------------------------------------------- #
# Grouping
# --------------------------------------------------------------------------- #
def test_network_cves_on_one_service_collapse_into_one_action() -> None:
    actions = plan_remediations(
        [_nmap_cve("CVE-2021-42013"), _nmap_cve("CVE-2021-41773"), _nmap_cve("CVE-2016-10009")]
    )
    assert len(actions) == 1
    action = actions[0]
    assert action.count == 3
    assert action.title == "Patch Apache httpd 2.4.49 on 10.0.0.5"
    assert action.cve_ids == ("CVE-2016-10009", "CVE-2021-41773", "CVE-2021-42013")


def test_same_product_on_different_hosts_stays_separate() -> None:
    actions = plan_remediations(
        [_nmap_cve("CVE-2021-42013", host="10.0.0.5"), _nmap_cve("CVE-2021-42013", host="10.0.0.6")]
    )
    assert len(actions) == 2
    assert {host for action in actions for host in action.hosts} == {"10.0.0.5", "10.0.0.6"}


def test_dependency_advisories_group_by_package_across_findings() -> None:
    actions = plan_remediations([_sbom("GHSA-aaaa"), _sbom("GHSA-bbbb"), _sbom("GHSA-cccc")])
    assert len(actions) == 1
    assert actions[0].title == "Upgrade lodash"
    assert actions[0].count == 3


def test_web_findings_group_by_title_class_across_endpoints() -> None:
    actions = plan_remediations(
        [
            _zap("Cross Site Scripting (Reflected)", host="a.example.com"),
            _zap("Cross Site Scripting (Reflected)", host="b.example.com"),
        ]
    )
    assert len(actions) == 1
    assert actions[0].title == "Remediate: Cross Site Scripting (Reflected)"
    assert actions[0].hosts == ("a.example.com", "b.example.com")


# --------------------------------------------------------------------------- #
# Instruction text (honest: solution, else template)
# --------------------------------------------------------------------------- #
def test_detail_prefers_scanner_solution() -> None:
    action = plan_remediations([_sbom("GHSA-aaaa", solution="Update lodash to 4.17.21 or later.")])[
        0
    ]
    assert action.detail == "Update lodash to 4.17.21 or later."


def test_detail_falls_back_to_template_without_a_solution() -> None:
    # Network CVE findings carry no solution text; the action must not invent a version.
    action = plan_remediations([_nmap_cve("CVE-2021-42013")])[0]
    assert action.detail == "Apply vendor updates for Apache httpd 2.4.49 on 10.0.0.5."
    assert "4.17" not in action.detail


def test_class_action_detail_template_when_no_solution() -> None:
    action = plan_remediations([_zap("Application Error Disclosure")])[0]
    assert action.detail == "Review the affected finding(s) and apply the appropriate fix."


# --------------------------------------------------------------------------- #
# Ranking + aggregates
# --------------------------------------------------------------------------- #
def test_known_exploited_action_ranks_first() -> None:
    actions = plan_remediations(
        [
            _zap("SQL Injection", host="a.example.com"),  # high, not KEV
            _nmap_cve("CVE-2021-42013", severity=Severity.HIGH, cvss=7.5, kev=True),
        ]
    )
    assert actions[0].kev is True
    assert actions[0].title.startswith("Patch Apache httpd")


def test_ranks_by_severity_then_total_risk() -> None:
    critical = _nmap_cve("CVE-2021-0001", product="nginx", severity=Severity.CRITICAL, cvss=9.8)
    two_mediums = [
        _sbom("GHSA-1", package="left"),
        _sbom("GHSA-2", package="left"),
    ]
    actions = plan_remediations([*two_mediums, critical])
    assert actions[0].highest is Severity.CRITICAL  # a single critical outranks two mediums


def test_aggregate_properties() -> None:
    action = plan_remediations(
        [
            _nmap_cve("CVE-2021-42013", severity=Severity.CRITICAL, cvss=9.8, kev=True),
            _nmap_cve("CVE-2021-41773", severity=Severity.HIGH, cvss=7.5),
        ]
    )[0]
    assert action.highest is Severity.CRITICAL
    assert action.kev is True
    assert action.max_risk >= action.total_risk - action.max_risk  # max is the largest single
    assert action.total_risk == sum(f.risk_score for f in action.findings)
    assert action.hosts == ("10.0.0.5",)


def test_findings_keep_incoming_order_within_a_group() -> None:
    first = _nmap_cve("CVE-2021-42013")
    second = _nmap_cve("CVE-2021-41773")
    action = plan_remediations([first, second])[0]
    assert [f.title for f in action.findings] == ["CVE-2021-42013", "CVE-2021-41773"]


def test_is_deterministic_regardless_of_input_order() -> None:
    findings = [
        _nmap_cve("CVE-2021-42013", kev=True),
        _sbom("GHSA-aaaa"),
        _zap("SQL Injection"),
    ]
    forward = [action.key for action in plan_remediations(findings)]
    backward = [action.key for action in plan_remediations(list(reversed(findings)))]
    assert forward == backward


def test_empty_plan() -> None:
    assert plan_remediations([]) == []


# --------------------------------------------------------------------------- #
# Renders
# --------------------------------------------------------------------------- #
def test_text_render_headline_and_table() -> None:
    text = render_remediation_text([_nmap_cve("CVE-2021-42013"), _nmap_cve("CVE-2021-41773")])
    assert "vulnpipe remediation plan — 1 action resolving 2 finding(s)" in text
    assert "Recommended actions" in text
    assert "Patch Apache httpd" in text


def test_text_render_empty() -> None:
    text = render_remediation_text([])
    assert "0 actions resolving 0 finding(s)" in text
    assert "No findings to remediate." in text


def test_text_render_top_limit_notes_remainder() -> None:
    findings = [
        _nmap_cve("CVE-2021-1", product="a"),
        _nmap_cve("CVE-2021-2", product="b"),
        _nmap_cve("CVE-2021-3", product="c"),
    ]
    text = render_remediation_text(findings, top=1)
    assert "and 2 more action(s)." in text


def test_markdown_render_table_and_escaping() -> None:
    finding = make_finding(
        source="zap",
        host="app.example.com",
        title="Weird | title",
        severity=Severity.LOW,
        solution="Do | this",
    )
    md = render_remediation_markdown([finding])
    assert md.startswith("# vulnpipe remediation plan")
    assert "**1 recommended action** resolving **1 findings**." in md
    assert "Weird \\| title" in md  # pipe escaped in the title cell
    assert "Do \\| this" in md  # pipe escaped in the recommendation cell


def test_markdown_render_empty() -> None:
    md = render_remediation_markdown([])
    assert "_No findings to remediate._" in md


def test_markdown_top_limit_notes_remainder() -> None:
    findings = [_nmap_cve("CVE-1", product="a"), _nmap_cve("CVE-2", product="b")]
    md = render_remediation_markdown(findings, top=1)
    assert "1 more action(s)" in md


def test_payload_shape() -> None:
    payload = remediation_to_payload(
        [_nmap_cve("CVE-2021-42013", kev=True), _nmap_cve("CVE-2021-41773")]
    )
    assert payload["summary"] == {"actions": 1, "findings": 2}
    actions = payload["actions"]
    assert isinstance(actions, list)
    action = actions[0]
    assert action["rank"] == 1
    assert action["finding_count"] == 2
    assert action["kev"] is True
    assert action["highest"] == "high"
    assert action["hosts"] == ["10.0.0.5"]
    assert set(action["cve_ids"]) == {"CVE-2021-42013", "CVE-2021-41773"}
    assert len(action["fingerprints"]) == 2


def test_payload_top_limits_actions_but_not_summary() -> None:
    findings = [_nmap_cve("CVE-1", product="a"), _nmap_cve("CVE-2", product="b")]
    payload = remediation_to_payload(findings, top=1)
    assert payload["summary"] == {"actions": 2, "findings": 2}
    assert len(payload["actions"]) == 1


def test_action_is_frozen() -> None:
    action = RemediationAction(key="k", title="t", detail="d", findings=())
    assert action.count == 0
    assert action.max_risk == 0
