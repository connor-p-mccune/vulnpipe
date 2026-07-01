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

from vulnpipe.enrichment.enricher import enrich_findings
from vulnpipe.enrichment.kev_client import KevEntry, parse_kev_catalog
from vulnpipe.processing import deduplicate, prioritize
from vulnpipe.reporting import get_reporter
from vulnpipe.scanners.nmap_scanner import parse_nmap_xml
from vulnpipe.scanners.zap_scanner import normalize_alerts

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
EXAMPLES = ROOT / "examples"

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
    findings = prioritize(deduplicate(enriched))

    for fmt, filename in (
        ("json", "sample-report.json"),
        ("html", "sample-report.html"),
        ("markdown", "sample-report.md"),
        ("csv", "sample-report.csv"),
    ):
        (EXAMPLES / filename).write_text(get_reporter(fmt).render(findings), encoding="utf-8")
        print(f"wrote examples/{filename}")


if __name__ == "__main__":
    main()
