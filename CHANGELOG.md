# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- CISA KEV (Known Exploited Vulnerabilities) enrichment: findings whose CVE is in
  the catalog are flagged `kev=True` with catalog context (date added, ransomware
  use) in metadata. A `kev` field on `Finding` and a `kev_enabled` enrichment flag.
- Composite `risk_score` (0–100) computed on every finding: a transparent blend of
  technical impact (CVSS/severity) and exploitation likelihood (KEV, then EPSS),
  surfaced in every report format and stripped on JSON round-trip like the fingerprint.
- Markdown report format (`report --format markdown`, `scan --markdown`) for
  pull-request comments and Slack: headline totals, a severity table, and a
  prioritized findings table with risk score, CVSS, EPSS, and a KEV marker.
- CSV report format (`report --format csv`) — one row per finding for a spreadsheet
  or data-frame; columns mirror the JSON fields plus fingerprint and risk score.
- Prometheus report format (`report --format prometheus`) — text-exposition gauges
  (findings by severity/source, known-exploited count, distinct hosts, peak risk) for
  the node_exporter textfile collector or a Pushgateway.
- HTML report: a known-exploited summary card, KEV highlighting in the per-host
  breakdown, risk-score and KEV columns, EPSS shown as a percentage, and a
  client-side filter toolbar (search, severity, known-exploited-only).
- `scripts/regenerate_examples.py` to rebuild the committed sample reports (now also
  emitting Markdown and CSV) deterministically from the fixtures.
- `stats` CLI command: a terminal summary of a findings JSON (severity breakdown,
  top findings by risk, and worst-affected hosts) rendered with Rich tables.
- `trend` CLI command and `ci/trends.py`: analyze a chronological series of findings
  JSONs — per-scan totals and severity mix, findings introduced/resolved between
  scans (matched by fingerprint), and the critical+high backlog direction (text/JSON).
- `validate` CLI command and `core/planner.py`: a dry run that resolves a config into
  a scan plan (in-scope network/web targets, enrichment sources, required secret env
  vars) and flags out-of-scope targets or an empty scope, without scanning.
- `schema` CLI command: print the JSON Schema for the targets/scope config file, for
  editor validation and autocomplete.
- A reusable composite GitHub Action (`action.yml`) that installs vulnpipe, runs an
  authorized scan, and gates the build — with inputs passed through the environment
  (never interpolated into the shell) to avoid command injection.
- `notify` CLI command and `notify/` package: post a findings summary to a
  Slack-compatible incoming webhook, with the webhook URL resolved from the
  environment (a secret, never logged) and message text escaped for Slack mrkdwn.

### Changed
- Prioritization now ranks known-exploited (KEV) findings ahead of equally severe
  ones, as a tie-breaker within a severity band (severity → KEV → CVSS → EPSS →
  asset criticality → fingerprint).
- Continuous-integration workflow running the quality gates (ruff, black, mypy)
  and the test suite across Python 3.12 / 3.13 / 3.14, plus the integration suite.
- GitHub Pages publishing of the sample HTML report.
- PyPI publishing workflow via Trusted Publishing (OIDC) and `[project.urls]`.
- Architecture decision records (`docs/DECISIONS.md`) and this changelog.
- A self-hosted vulnerable-target lab overlay (`docker/docker-compose.lab.yml`,
  `configs/targets.lab.yaml`) and a case-study guide (`docs/case-study.md`).
- README badges, a Mermaid pipeline diagram, a live-report link, and a
  reproducible terminal-demo tape (`assets/demo.tape`).

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

[Unreleased]: https://github.com/connor-p-mccune/vulnpipe/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/connor-p-mccune/vulnpipe/releases/tag/v0.1.0
