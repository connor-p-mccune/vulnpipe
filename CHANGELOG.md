# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Time-boxed risk acceptances** — false-positive allowlist entries accept an
  optional `reason` (the audit trail lives with the rule) and an inclusive
  `expires` date. A lapsed entry stops suppressing — the finding resurfaces in
  reports and the gate — and the scan logs a warning naming the expired
  acceptance, so suppressions get revisited instead of becoming silently
  permanent. Bare-string entries remain valid and accept indefinitely.
- **OpenVEX report format** — `report --format vex`, `scan --vex`, and
  `sbom --format vex` emit an [OpenVEX](https://openvex.dev) 0.2.0 document for
  exploitability-exchange tooling. Statements are produced only for findings citing
  a real CVE / OSV id and assert only the `affected` status (`not_affected` /
  `fixed` are human judgements, never fabricated); KEV listings surface in
  `status_notes`, products carry purls for SBOM findings, the document `@id` is
  content-addressed, and the publication timestamp honors `SOURCE_DATE_EPOCH` for
  reproducible builds. The GitHub Action gains a matching `vex` input, and
  `examples/sample-vex.json` shows the output shape.
- **SBOM as a scan layer** — a scan config can list CycloneDX SBOMs under `sbom:`,
  and the orchestrator analyzes them against OSV.dev through the same injectable
  seam as the network and web layers, so supply-chain findings enrich, dedup,
  prioritize, diff, and gate alongside scanner output. SBOM files bypass the scope
  allowlist (local artifacts, nothing probed); an unreadable file degrades to a
  warning.
- **`diff --format markdown`** — render the baseline diff as a GitHub-flavored
  pull-request comment (new/persisting/resolved headline, a table of new findings,
  and a list of resolved ones).
- **`schema report` / `schema policy`** — the `schema` command now also prints the
  JSON Schema for the findings report envelope (finding items in serialization
  mode, so the computed fingerprint and risk score are part of the contract) and
  for a gate-policy file.
- **HTML dark theme** — the report palette moved onto CSS custom properties with a
  `prefers-color-scheme: dark` media query, so it follows the reader's OS theme.

## [0.3.0] - 2026-07-02

Standards context, policy-as-code gating, and supply-chain (SBOM) analysis.

### Added
- **Supply-chain (SBOM) analysis** — a new `sbom/` layer and `sbom` command:
  parse a CycloneDX component inventory, query the OSV.dev advisory database per
  component (cached, retried, failure degrades to empty), and normalize each
  advisory into a standard finding (severity from the advisory's own CVSS vector;
  remediation from its declared fixed versions). Findings are EPSS/KEV-enriched,
  deduplicated, and prioritized, so `report` / `stats` / `diff` / `baseline` /
  `trend` / `gate` all work on supply-chain results unchanged. Passive by design:
  no scope or `--authorized` needed.
- **OWASP Top 10 / CWE Top 25 mapping** (`core/standards.py`) — curated official
  mappings applied at render time: an OWASP breakdown section, CWE Top 25 card,
  and OWASP column in HTML; OWASP tables in Markdown and `stats`; an `owasp` CSV
  column; and `external/owasp/...` SARIF rule tags plus an `owasp` result
  property. Unmapped CWEs are reported as unmapped, never forced into a category.
- **Policy-as-code gating** (`ci/policy.py`, `configs/policy.example.yaml`) — a
  declarative YAML gate: per-severity budgets for new findings, a total-new cap,
  a composite risk-score threshold, and a block on new known-exploited (KEV)
  findings. `scan --policy` swaps it in for the severity gate (JUnit failure
  bodies describe the violated rules), and the composite GitHub Action gains a
  matching `policy` input.
- **`gate` command** — re-evaluate the CI gate over an existing findings JSON
  without rescanning, against a baseline (or treating everything as new), with a
  policy file or the severity/risk options; text or JSON verdict and a non-zero
  exit on violation.
- **`badge` command** (`reporting/badge.py`) — render findings into a
  deterministic shields-style SVG status badge (worst severity bands, report
  palette colors, a `!` marker for known-exploited) for a README or dashboard.
- **Expandable finding details in the HTML report** — a per-finding disclosure
  with description, a highlighted remediation line, the CVSS vector, and up to
  five reference links (only http(s) references become hyperlinks; anything else
  stays inert text).
- Risk-score CI gating: `scan --gate-risk-score N` (and a matching GitHub Action
  input) fails the build on a new finding whose composite risk score is at least `N`,
  in addition to the severity gate — so an actively-exploited Medium can fail CI even
  though it sits below the severity bar.
- SARIF results now carry the composite `riskScore` and a `kev` flag in their
  properties, so those signals reach the GitHub Security tab and other SARIF consumers.
- JSON POST support in the shared enrichment HTTP client (same throttle/retry
  semantics), used by the OSV integration.

## [0.2.0] - 2026-07-01

Risk intelligence and integrations: known-exploited (KEV) cross-referencing, a
composite risk score, four new report formats, and five new CLI commands.

### Added
- **CISA KEV enrichment** — findings whose CVE is in the Known Exploited
  Vulnerabilities catalog are flagged `kev=True` with catalog context (date added,
  ransomware use) in metadata. A `kev` field on `Finding` and a `kev_enabled` flag.
- **Composite `risk_score` (0–100)** computed on every finding: a transparent blend of
  technical impact (CVSS/severity) and exploitation likelihood (KEV, then EPSS),
  surfaced in every report format and stripped on JSON round-trip like the fingerprint.
- **Markdown report format** (`report --format markdown`, `scan --markdown`) for
  pull-request comments and Slack: headline totals, a severity table, and a
  prioritized findings table with risk score, CVSS, EPSS, and a KEV marker.
- **CSV report format** (`report --format csv`) — one row per finding for a spreadsheet
  or data-frame; columns mirror the JSON fields plus fingerprint and risk score.
- **Prometheus report format** (`report --format prometheus`) — text-exposition gauges
  (findings by severity/source, known-exploited count, distinct hosts, peak risk) for
  the node_exporter textfile collector or a Pushgateway.
- **HTML report enhancements** — a known-exploited summary card, KEV highlighting in
  the per-host breakdown, risk-score and KEV columns, EPSS shown as a percentage, and a
  client-side filter toolbar (search, severity, known-exploited-only).
- **`stats` command** — a terminal summary of a findings JSON (severity breakdown, top
  findings by risk, and worst-affected hosts) rendered with Rich tables.
- **`trend` command** and `ci/trends.py` — analyze a chronological series of findings
  JSONs: per-scan totals and severity mix, findings introduced/resolved between scans
  (matched by fingerprint), and the critical+high backlog direction (text/JSON).
- **`validate` command** and `core/planner.py` — a dry run that resolves a config into
  a scan plan (in-scope network/web targets, enrichment sources, required secret env
  vars) and flags out-of-scope targets or an empty scope, without scanning.
- **`notify` command** and the `notify/` package — post a findings summary to a
  Slack-compatible incoming webhook, with the webhook URL resolved from the environment
  (a secret, never logged) and message text escaped for Slack mrkdwn.
- **`schema` command** — print the JSON Schema for the targets/scope config file, for
  editor validation and autocomplete.
- A reusable composite **GitHub Action** (`action.yml`) that installs vulnpipe, runs an
  authorized scan, and gates the build — with inputs passed through the environment
  (never interpolated into the shell) to avoid command injection.
- `scripts/regenerate_examples.py` to rebuild the committed sample reports (now also
  emitting Markdown and CSV) deterministically from the fixtures.
- Continuous-integration workflow running the quality gates (ruff, black, mypy) and the
  test suite across Python 3.12 / 3.13 / 3.14, plus the integration suite; GitHub Pages
  publishing of the sample HTML report; a PyPI Trusted-Publishing (OIDC) workflow and
  `[project.urls]`; architecture decision records (`docs/DECISIONS.md`) and this
  changelog; a self-hosted vulnerable-target lab overlay and case-study guide; and
  README badges, a Mermaid diagram, a live-report link, and a demo tape.

### Changed
- Prioritization now ranks known-exploited (KEV) findings ahead of equally severe ones,
  as a tie-breaker within a severity band (severity → KEV → CVSS → EPSS → asset
  criticality → fingerprint).

## [0.1.0] - 2026-06-24

Initial release: an end-to-end network + web vulnerability scanning pipeline
(detection and reporting only).

### Added
- **Core model** — a frozen pydantic `Finding` (plus `Host` / `Service` and the
  `Severity` / `Confidence` / `AssetCriticality` enums) with a stable
  `sha256(host | port | source | plugin_or_alert_id | normalized_title)`
  fingerprint; a rich-backed structured logger; and YAML + environment config
  loading with a strict schema.
- **Authorization guards** — every scan requires an explicit `--authorized`
  acknowledgement and a scope allowlist; out-of-scope targets are a hard error.
- **Scanners** — an Nmap network scanner (services, versions, OS, and `vulners`
  CVE findings) and an OWASP ZAP web scanner (spider + active scan + alerts),
  each normalizing to `Finding`. Authenticated ZAP scanning (form / header-JWT /
  script contexts) with credentials resolved from the environment.
- **Enrichment** — CVSS parsing plus cached NVD and EPSS lookups that fill, but
  never fabricate, CVSS/EPSS fields.
- **Processing** — pure transforms: normalize, deduplicate by fingerprint,
  false-positive filtering (allowlist + confidence floor), and prioritization
  (severity → CVSS → EPSS → asset criticality).
- **Reporting** — deterministic JSON (canonical), HTML (summary, severity chart,
  per-host breakdown, sortable table), and SARIF 2.1.0 reporters.
- **CI integration** — a baseline store, a new/persisting/resolved differ, a
  severity gate (fails only on *new* findings at or above a threshold), and JUnit
  XML output.
- **Orchestrator + CLI** — `run_pipeline` (bounded thread pool with capped ZAP
  concurrency) and a Typer CLI (`scan`, `report`, `diff`, `baseline`, `version`).
- **Packaging** — a multi-stage Docker image and a one-command compose lab
  (scanner + ZAP daemon); Apache-2.0 licensed.

[Unreleased]: https://github.com/connor-p-mccune/vulnpipe/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/connor-p-mccune/vulnpipe/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/connor-p-mccune/vulnpipe/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/connor-p-mccune/vulnpipe/releases/tag/v0.1.0
