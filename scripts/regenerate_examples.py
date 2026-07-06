"""Regenerate the committed sample reports in ``examples/``.

Runs the real pipeline stages over the project's committed test fixtures (a captured
Nmap ``vulners`` XML scan and a sample ZAP ``core.alerts`` payload), so the samples
are fully deterministic and contain only synthetic lab data. Network enrichment
(NVD / EPSS) is intentionally skipped -- those need live services and would make the
output non-deterministic -- but CISA KEV status is applied *offline* from a small,
real slice of the catalog so the samples showcase known-exploited findings honestly.

Run from the repository root:

    python scripts/regenerate_examples.py
"""

from __future__ import annotations

import json
from pathlib import Path

from vulnpipe.core.config import AssetRule, PrioritizationConfig
from vulnpipe.core.models import AssetCriticality
from vulnpipe.enrichment.enricher import enrich_findings
from vulnpipe.enrichment.kev_client import KevEntry, parse_kev_catalog
from vulnpipe.processing import annotate_ownership, deduplicate, prioritize
from vulnpipe.reporting import (
    get_reporter,
    render_badge,
    render_cyclonedx,
    render_gitlab,
    render_remediation_markdown,
    render_vex,
)
from vulnpipe.scanners.nmap_scanner import parse_nmap_xml
from vulnpipe.scanners.zap_scanner import normalize_alerts

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
EXAMPLES = ROOT / "examples"

# OpenVEX requires a publication timestamp on the document. The committed sample is
# pinned to a fixed stamp so regeneration stays byte-for-byte deterministic; a real
# run stamps the actual publication time (or honors SOURCE_DATE_EPOCH).
_VEX_TIMESTAMP = "2026-01-01T00:00:00Z"

# The GitLab security report likewise carries a scan timestamp; pin it for the
# committed sample (a real run honors SOURCE_DATE_EPOCH or stamps the current time).
_GITLAB_TIMESTAMP = "2026-01-01T00:00:00"

# The CycloneDX VDR carries a BOM metadata timestamp; pin it for the committed sample
# (a real run honors SOURCE_DATE_EPOCH or stamps the current time).
_CYCLONEDX_TIMESTAMP = "2026-01-01T00:00:00Z"

# A synthetic ownership map for the sample's lab hosts, so the samples demonstrate
# triage routing (the "by owner" views). The web app is owned by an appsec team; the
# internal network range by a platform team.
_OWNERSHIP = PrioritizationConfig(
    assets=[
        AssetRule(
            host="*.lab.example.com",
            criticality=AssetCriticality.HIGH,
            owner="appsec-team",
            tags=["web", "external"],
        ),
        AssetRule(
            host="10.0.0.0/24",
            criticality=AssetCriticality.MEDIUM,
            owner="platform-team",
            tags=["infrastructure"],
        ),
    ]
)


# A real slice of the CISA KEV catalog covering the two Apache HTTP Server path
# traversal CVEs present in the fixture scan (CVE-2021-41773 / CVE-2021-42013). Both
# are genuinely listed in the catalog -- this is not fabricated exploitation status.
_KEV_CATALOG_JSON = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-41773",
            "vendorProject": "Apache",
            "product": "HTTP Server",
            "vulnerabilityName": "Apache HTTP Server Path Traversal Vulnerability",
            "dateAdded": "2021-11-03",
            "knownRansomwareCampaignUse": "Unknown",
        },
        {
            "cveID": "CVE-2021-42013",
            "vendorProject": "Apache",
            "product": "HTTP Server",
            "vulnerabilityName": "Apache HTTP Server Path Traversal Vulnerability",
            "dateAdded": "2021-11-03",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ]
}


class _OfflineKev:
    """A minimal KEV client backed by a fixed, in-memory catalog (no network)."""

    def __init__(self, catalog: dict[str, KevEntry]) -> None:
        self._catalog = catalog

    def get_catalog(self) -> dict[str, KevEntry]:
        return self._catalog


def main() -> None:
    nmap_findings = parse_nmap_xml((FIXTURES / "nmap_vulners.xml").read_text(encoding="utf-8"))
    zap_alerts = json.loads((FIXTURES / "sample_zap_alerts.json").read_text(encoding="utf-8"))
    zap_findings = normalize_alerts(zap_alerts["alerts"])

    kev = _OfflineKev(parse_kev_catalog(_KEV_CATALOG_JSON))
    enriched = enrich_findings([*nmap_findings, *zap_findings], kev=kev)  # type: ignore[arg-type]
    findings = annotate_ownership(
        prioritize(deduplicate(enriched)),
        owner_for=_OWNERSHIP.owner_for,
        tags_for=_OWNERSHIP.tags_for,
    )

    for fmt, filename in (
        ("json", "sample-report.json"),
        ("html", "sample-report.html"),
        ("markdown", "sample-report.md"),
        ("csv", "sample-report.csv"),
    ):
        (EXAMPLES / filename).write_text(get_reporter(fmt).render(findings), encoding="utf-8")
        print(f"wrote examples/{filename}")

    (EXAMPLES / "sample-badge.svg").write_text(render_badge(findings), encoding="utf-8")
    print("wrote examples/sample-badge.svg")

    vex = render_vex(findings, timestamp=_VEX_TIMESTAMP)
    (EXAMPLES / "sample-vex.json").write_text(vex, encoding="utf-8")
    print("wrote examples/sample-vex.json")

    gitlab = render_gitlab(findings, timestamp=_GITLAB_TIMESTAMP)
    (EXAMPLES / "sample-report.gitlab.json").write_text(gitlab, encoding="utf-8")
    print("wrote examples/sample-report.gitlab.json")

    cyclonedx = render_cyclonedx(findings, timestamp=_CYCLONEDX_TIMESTAMP)
    (EXAMPLES / "sample-report.cyclonedx.json").write_text(cyclonedx, encoding="utf-8")
    print("wrote examples/sample-report.cyclonedx.json")

    remediation = render_remediation_markdown(findings)
    (EXAMPLES / "sample-remediation.md").write_text(remediation, encoding="utf-8")
    print("wrote examples/sample-remediation.md")


if __name__ == "__main__":
    main()
