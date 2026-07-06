"""Unit tests for asset ownership: annotation, config resolvers, and surfacing.

Covers the pure `annotate_ownership` transform, the `PrioritizationConfig` owner /
tags resolvers, the `group_by_owner` view-model, every reporter that surfaces
ownership, and the orchestrator wiring that stamps it during a scan.
"""

import csv
import io

from vulnpipe.core.config import (
    AssetCriticality,
    AssetRule,
    Config,
    PrioritizationConfig,
    Scope,
    Target,
)
from vulnpipe.core.models import Finding, Severity
from vulnpipe.core.orchestrator import EnrichmentClients, run_pipeline
from vulnpipe.processing import annotate_ownership
from vulnpipe.processing.normalizer import make_finding
from vulnpipe.reporting.csv_reporter import render_csv
from vulnpipe.reporting.html_reporter import render_html
from vulnpipe.reporting.markdown_reporter import render_markdown
from vulnpipe.reporting.stats import render_stats, stats_to_payload
from vulnpipe.reporting.summary import (
    UNASSIGNED_OWNER,
    finding_owner,
    finding_tags,
    group_by_owner,
    owners_present,
)


def _finding(host: str, *, severity: Severity = Severity.MEDIUM, **overrides: object) -> Finding:
    base: dict[str, object] = {
        "source": "zap",
        "host": host,
        "title": f"finding on {host}",
        "severity": severity,
        "plugin_id": "1",
    }
    base.update(overrides)
    return make_finding(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# annotate_ownership
# --------------------------------------------------------------------------- #
def test_annotate_stamps_owner_and_tags_into_metadata() -> None:
    annotated = annotate_ownership(
        [_finding("10.0.0.10")],
        owner_for=lambda host: "team-web",
        tags_for=lambda host: ["pci", "external"],
    )[0]
    assert annotated.metadata["owner"] == "team-web"
    assert annotated.metadata["tags"] == ["pci", "external"]


def test_annotate_preserves_fingerprint_and_existing_metadata() -> None:
    original = _finding("10.0.0.10", metadata={"service": "http"})
    annotated = annotate_ownership([original], owner_for=lambda host: "team-web")[0]
    assert annotated.fingerprint == original.fingerprint  # ownership is not fingerprinted
    assert annotated.metadata["service"] == "http"  # existing metadata kept
    assert annotated.metadata["owner"] == "team-web"


def test_annotate_passes_through_unchanged_without_owner_or_tags() -> None:
    original = _finding("10.0.0.10")
    result = annotate_ownership([original], owner_for=lambda host: None, tags_for=lambda host: [])
    assert result[0] is original  # identity: no copy when nothing to stamp


def test_annotate_default_resolvers_are_a_no_op() -> None:
    original = _finding("10.0.0.10")
    assert annotate_ownership([original])[0] is original


def test_annotate_sets_only_the_present_fields() -> None:
    owner_only = annotate_ownership([_finding("h")], owner_for=lambda host: "team")[0]
    assert "tags" not in owner_only.metadata
    tags_only = annotate_ownership([_finding("h")], tags_for=lambda host: ["x"])[0]
    assert "owner" not in tags_only.metadata


# --------------------------------------------------------------------------- #
# PrioritizationConfig resolvers
# --------------------------------------------------------------------------- #
def _prioritization() -> PrioritizationConfig:
    return PrioritizationConfig(
        default_criticality=AssetCriticality.LOW,
        assets=[
            AssetRule(
                host="10.0.0.10",
                criticality=AssetCriticality.HIGH,
                owner="team-web",
                tags=["pci", "external"],
            ),
            AssetRule(
                host="*.lab.example.com", criticality=AssetCriticality.MEDIUM, owner="team-x"
            ),
        ],
    )


def test_owner_and_tags_resolve_from_the_first_matching_rule() -> None:
    prio = _prioritization()
    assert prio.owner_for("10.0.0.10") == "team-web"
    assert prio.tags_for("10.0.0.10") == ("pci", "external")
    assert prio.criticality_for("10.0.0.10") == AssetCriticality.HIGH


def test_wildcard_rule_matches_and_criticality_still_works() -> None:
    prio = _prioritization()
    assert prio.owner_for("app.lab.example.com") == "team-x"
    assert prio.tags_for("app.lab.example.com") == ()
    assert prio.criticality_for("app.lab.example.com") == AssetCriticality.MEDIUM


def test_unmatched_host_has_no_owner_and_default_criticality() -> None:
    prio = _prioritization()
    assert prio.owner_for("192.168.1.1") is None
    assert prio.tags_for("192.168.1.1") == ()
    assert prio.criticality_for("192.168.1.1") == AssetCriticality.LOW


# --------------------------------------------------------------------------- #
# summary helpers
# --------------------------------------------------------------------------- #
def test_finding_owner_and_tags_read_metadata() -> None:
    finding = _finding("h", metadata={"owner": "team-a", "tags": ["x", "y", 3, " "]})
    assert finding_owner(finding) == "team-a"
    assert finding_tags(finding) == ("x", "y")  # non-strings and blanks dropped


def test_finding_owner_blank_is_unassigned() -> None:
    assert finding_owner(_finding("h", metadata={"owner": "  "})) is None
    assert finding_owner(_finding("h")) is None


def test_owners_present() -> None:
    assert owners_present([_finding("h", metadata={"owner": "team-a"})]) is True
    assert owners_present([_finding("h")]) is False


def test_group_by_owner_orders_assigned_first_then_unassigned() -> None:
    findings = [
        _finding("a", severity=Severity.HIGH, metadata={"owner": "team-a"}),
        _finding("b", severity=Severity.CRITICAL, metadata={"owner": "team-b"}),
        _finding("c", severity=Severity.LOW),
    ]
    groups = group_by_owner(findings)
    assert [(g.owner, g.assigned) for g in groups] == [
        ("team-b", True),  # assigned, worst severity first
        ("team-a", True),
        (UNASSIGNED_OWNER, False),  # the coverage gap always sorts last
    ]
    assert groups[0].highest == Severity.CRITICAL
    assert len(groups[2].findings) == 1


def test_group_by_owner_breaks_severity_ties_by_name() -> None:
    findings = [
        _finding("a", severity=Severity.HIGH, metadata={"owner": "team-z"}),
        _finding("b", severity=Severity.HIGH, metadata={"owner": "team-a"}),
    ]
    assert [g.owner for g in group_by_owner(findings)] == ["team-a", "team-z"]


# --------------------------------------------------------------------------- #
# Reporter surfacing
# --------------------------------------------------------------------------- #
def _owned() -> list[Finding]:
    return [_finding("10.0.0.10", metadata={"owner": "team-web", "tags": ["pci", "external"]})]


def test_csv_carries_owner_and_tags_columns() -> None:
    rows = list(csv.DictReader(io.StringIO(render_csv(_owned()))))
    assert rows[0]["owner"] == "team-web"
    assert rows[0]["tags"] == "pci;external"


def test_markdown_shows_ownership_only_when_owned() -> None:
    assert "## Ownership" in render_markdown(_owned())
    assert "team-web" in render_markdown(_owned())
    assert "## Ownership" not in render_markdown([_finding("10.0.0.10")])


def test_stats_text_shows_owner_table_only_when_owned() -> None:
    assert "By owner" in render_stats(_owned())
    assert "team-web" in render_stats(_owned())
    assert "By owner" not in render_stats([_finding("10.0.0.10")])


def test_stats_text_labels_the_unassigned_bucket() -> None:
    mixed = [_finding("a", metadata={"owner": "team-web"}), _finding("b")]
    output = render_stats(mixed)
    assert "team-web" in output
    assert "unassigned" in output  # the coverage-gap bucket is labelled in the table


def test_stats_payload_by_owner() -> None:
    payload = stats_to_payload(_owned())
    assert payload["by_owner"] == [
        {"owner": "team-web", "assigned": True, "findings": 1, "highest": "medium"}
    ]
    assert stats_to_payload([_finding("10.0.0.10")])["by_owner"] == []


def test_html_shows_ownership_section_and_column_only_when_owned() -> None:
    owned = render_html(_owned())
    assert "<h2>Ownership</h2>" in owned
    assert "Owner</th>" in owned  # the findings-table column
    assert "team-web" in owned
    unowned = render_html([_finding("10.0.0.10")])
    assert "<h2>Ownership</h2>" not in unowned
    assert "Owner</th>" not in unowned


def test_json_round_trip_preserves_owner_metadata() -> None:
    from vulnpipe.reporting.json_reporter import build_report, report_to_findings

    # The canonical JSON carries metadata, so ownership survives a report round-trip.
    restored = report_to_findings(build_report(_owned()))
    assert restored[0].metadata["owner"] == "team-web"
    assert restored[0].metadata["tags"] == ["pci", "external"]


# --------------------------------------------------------------------------- #
# Orchestrator wiring
# --------------------------------------------------------------------------- #
def test_run_pipeline_stamps_ownership_from_config() -> None:
    config = Config(
        scope=Scope(hosts=["10.0.0.0/24"]),
        targets=[Target(host="10.0.0.10")],
        prioritization=PrioritizationConfig(
            assets=[
                AssetRule(host="10.0.0.10", criticality=AssetCriticality.HIGH, owner="team-web")
            ]
        ),
    )
    result = run_pipeline(
        config,
        authorized=True,
        enrichment=EnrichmentClients(),
        run_network=lambda _c: [_finding("10.0.0.10", severity=Severity.HIGH)],
        run_web=lambda _c, _u: [],
        run_nuclei=lambda _c, _u: [],
        run_sbom=lambda _c: [],
        run_imports=lambda _c: [],
    )
    assert result.findings[0].metadata["owner"] == "team-web"
