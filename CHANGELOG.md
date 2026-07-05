# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0] - 2026-07-04

Interoperability: ingest the output of the scanners you already run.

### Added
- **Third-party scanner import** (`ingest/`, `convert` command) — normalize a
  [Trivy](https://trivy.dev/) (`trivy image -f json`) or
  [Grype](https://github.com/anchore/grype) (`grype -o json`) JSON report into the
  shared `Finding` model, so a container or SBOM scan you already run flows through
  vulnpipe's prioritization, remediation planning, gating, SLAs, and reports.
  `vulnpipe convert -i trivy.json --from trivy` emits deduplicated, prioritized
  findings JSON (or any report format); package identity is carried in metadata so
  imports feed the remediation planner, and they `merge` with native scans under one
  baseline and gate. Each parser is a pure `dict → list[Finding]` function that maps
  the source report's own severity, CVSS, CVE/CWE ids, and fix version — inventing
  nothing — and raises `IngestError` on a wrong-shaped document. Passive, so it needs
  no scope or `--authorized`.

## [0.6.0] - 2026-07-04

Vulnerability management over time: finding age, remediation SLAs, and a visual trend.

### Added
- **Remediation SLAs** (`ci/sla.py`, `sla` command) — govern *dwell time*, not just
  new risk: an `SlaPolicy` declares per-severity remediation deadlines in days
  (`configs/sla.example.yaml`), and `vulnpipe sla` flags every finding open past its
  deadline, measuring age from the baseline's first-seen date against `--as-of`
  (default today, injectable for reproducible CI). It exits non-zero on a breach, and
  a finding with no recorded first-seen date is untracked and never breaches — unknown
  age is never a violation. Inline `--critical-days` / `--high-days` / … options or a
  policy file; `schema sla` prints the policy schema.
- **Baseline age tracking** — each baseline entry gains an optional `first_seen` date,
  stamped by `baseline --track-age` and preserved across merges so age counts from a
  finding's true first appearance. The field is omitted from the on-disk form when
  unset, so an age-untracked baseline stays byte-identical to one written before the
  field existed.
- **`trend --format html`** — render the multi-scan trend as a self-contained,
  shareable HTML page: an inline SVG stacked bar chart of the severity mix across the
  scan series (pure, unit-tested geometry), a direction verdict, a legend, and a
  per-scan metrics table. Deterministic and fully HTML-escaped like the other HTML
  outputs.

## [0.5.0] - 2026-07-04

Remediation intelligence, a modern template-based scanner, and CI-platform reach.

### Added
- **Remediation planning** (`reporting/remediation.py`, `remediate` command) —
  collapse the findings list into a ranked, deduplicated worklist: findings are
  grouped by the action that resolves them (a dependency by package, a network
  service by product-per-host, everything else by weakness class) and ordered by
  the risk each fix removes (known-exploited first, then severity, then total risk,
  then count). The instruction reuses the scanner's own remediation text when it
  exists and otherwise falls back to a template that never invents a fixed version.
  Surfaced by `vulnpipe remediate` (text / JSON / Markdown, with `--top`), a
  "Remediation plan" panel in the HTML report, and a "Top remediations" table in the
  terminal `stats` view — all from one pure planner.
- **Nuclei scanner** (`scanners/nuclei_scanner.py`) — an optional third detection
  layer alongside Nmap and ZAP, driving ProjectDiscovery's `nuclei` over the same
  in-scope web URLs with template-based CVE / misconfiguration / exposure checks. It
  registers through the scanner registry, parses nuclei's JSONL (mapping template
  severity, CVE/CWE classification, CVSS, and match location onto findings), and is
  wired as an injectable orchestrator layer. Detection-only (no fuzzing/exploitation
  flags, no replayable payload on a finding) and off by default (`nuclei.enabled`),
  so existing runs are byte-for-byte unchanged; every failure mode degrades to a
  logged warning. `validate` reports whether the layer is enabled.
- **GitLab security report** (`report --format gitlab`) — a GitLab-compatible
  security report for the GitLab Vulnerability Report and the merge-request security
  widget, complementing SARIF's GitHub coverage. A DAST-style export: the
  vulnerability id is the stable fingerprint (GitLab tracks issues across pipelines),
  identifiers carry the real CVEs/CWEs plus a vulnpipe rule id so the list is never
  empty, and severity maps onto GitLab's vocabulary. The schema-required scan times
  honor `SOURCE_DATE_EPOCH` like the OpenVEX timestamp; the pure builder omits them
  for snapshot stability.
- `examples/sample-report.gitlab.json` and `examples/sample-remediation.md` join the
  committed sample set, regenerated deterministically from the same fixtures.

## [0.4.0] - 2026-07-03

Exploitability exchange (OpenVEX), extensibility (plugins), and reporting reach.

### Added
- **`diff --format html`** — render the baseline diff as a self-contained,
  shareable HTML page: new/persisting/resolved headline and verdict, a table of
  newly introduced findings (severity chips, risk score, KEV marker, CVEs), the
  resolved ones, and the persisting ones behind a disclosure. Deterministic and
  fully HTML-escaped, so it is safe to publish as a build artifact.
- **Ranked OWASP Top 10 chart in the HTML report** — the flat OWASP list is now a
  horizontal SVG bar chart ordered by prevalence (busiest weakness class first,
  ties broken by OWASP rank), with the full category title and count per row. Pure,
  unit-tested geometry (`build_owasp_chart`), deterministic like the severity chart.
- **`merge` command** — combine findings JSONs from separate runs (a network
  scan plus an SBOM analysis, or scans of different segments) into one
  deduplicated, re-prioritized report, so a single baseline, diff, and gate can
  cover everything. Findings sharing a fingerprint collapse into the richest
  instance, exactly as the in-pipeline deduplicator does.
- **`schema false-positives`** — the `schema` command now also prints the JSON
  Schema for the false-positive allowlist, covering the time-boxed acceptance
  fields (`reason`, `expires`) for editor validation.
- **Plugin discovery via entry points** — installed packages can advertise extra
  scanners and report formats under the `vulnpipe.scanners` / `vulnpipe.reporters`
  entry-point groups; they are discovered and registered at CLI startup and listed
  by the new `plugins` command. Discovery is defensive and deterministic: sorted
  processing order, a broken plugin degrades to a logged warning, and a plugin can
  never shadow a built-in name.
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

[Unreleased]: https://github.com/connor-p-mccune/vulnpipe/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/connor-p-mccune/vulnpipe/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/connor-p-mccune/vulnpipe/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/connor-p-mccune/vulnpipe/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/connor-p-mccune/vulnpipe/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/connor-p-mccune/vulnpipe/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/connor-p-mccune/vulnpipe/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/connor-p-mccune/vulnpipe/releases/tag/v0.1.0
