# Example reports

These are sample vulnpipe reports so you can see the output shape before running a
scan of your own.

They are rendered from the project's committed **test fixtures** — a captured Nmap
`vulners` XML scan and a sample ZAP `core.alerts` payload — so they are fully
deterministic and contain only **synthetic lab data** (RFC 1918 addresses and
`example.com` / `example.net` hosts). They are not the output of a real scan
against a real system.

| File | What it is |
| --- | --- |
| [`sample-report.json`](sample-report.json) | The canonical, lossless JSON report — exactly what `vulnpipe scan` writes to `results/latest.json` and what `report` / `diff` / `baseline` read back. |
| [`sample-report.html`](sample-report.html) | The human-readable HTML report (summary, inline SVG severity chart, per-host breakdown, and a filterable, sortable findings table). Open it in a browser. |
| [`sample-report.md`](sample-report.md) | The Markdown report — a pull-request / Slack–friendly summary. |
| [`sample-report.csv`](sample-report.csv) | The CSV report — one row per finding for a spreadsheet or data-frame. |
| [`sample-report.gitlab.json`](sample-report.gitlab.json) | The GitLab security report — the JSON GitLab ingests to populate its Vulnerability Report and merge-request security widget. Its scan `start_time` / `end_time` are pinned so the committed sample stays deterministic. |
| [`sample-remediation.md`](sample-remediation.md) | The remediation plan — findings collapsed into a ranked, deduplicated worklist (`vulnpipe remediate`), most impactful fix first. |
| [`sample-badge.svg`](sample-badge.svg) | The SVG status badge — the worst outstanding severities at a glance, for a README or dashboard. |
| [`sample-vex.json`](sample-vex.json) | The OpenVEX 0.2.0 document — machine-readable `affected` statements for every finding that cites a real CVE / OSV id, for exploitability-exchange tooling. Its publication `timestamp` is pinned so the committed sample stays deterministic. |
| [`sample-report.cyclonedx.json`](sample-report.cyclonedx.json) | The CycloneDX 1.5 vulnerability report (VDR) — a BOM whose `vulnerabilities` link each detected issue to the component it affects, for Dependency-Track and the `cyclonedx` CLI. Its `metadata.timestamp` is pinned so the committed sample stays deterministic. |

The sample contains 15 findings across 4 hosts (1 critical, 5 high, 2 medium,
2 low, 5 informational), shown in vulnpipe's prioritized order. Two of them are
flagged **known-exploited** (in the CISA KEV catalog) and carry a composite
`risk_score` — so the two Apache path-traversal CVEs surface at the top of their
severity band even when another finding scores higher on CVSS alone.

The sample also demonstrates **ownership routing**: a synthetic ownership map assigns
the web app to an `appsec-team` and the internal network range to a `platform-team`,
so the reports show the "by owner" breakdown (an Ownership section in the HTML and
Markdown reports, `owner` / `tags` columns in the CSV).

## Regenerating

From a checkout with the package installed (`pip install -e .`), run the committed
script from the repository root:

```bash
python scripts/regenerate_examples.py
```

It parses the fixtures, applies CISA KEV status offline (network NVD/EPSS enrichment
is skipped so the output stays deterministic), prioritizes, and writes every sample
format into this directory.
