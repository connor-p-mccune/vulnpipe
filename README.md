# vulnpipe

[![CI](https://github.com/connor-p-mccune/vulnpipe/actions/workflows/ci.yml/badge.svg)](https://github.com/connor-p-mccune/vulnpipe/actions/workflows/ci.yml)
[![coverage](https://img.shields.io/badge/coverage-98%25-brightgreen)](https://github.com/connor-p-mccune/vulnpipe/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.12%20%7C%203.13%20%7C%203.14-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Lint: ruff](https://img.shields.io/badge/lint-ruff-261230.svg)](https://github.com/astral-sh/ruff)
[![mypy: strict](https://img.shields.io/badge/mypy-strict-blue.svg)](https://mypy-lang.org/)

<p align="center">
  <img src="assets/demo.svg" alt="vulnpipe scanning two in-scope targets, prioritizing 15 findings, and failing the CI gate on new high/critical findings" width="760">
</p>

> Modular network + web vulnerability scanning pipeline. It orchestrates
> [Nmap](https://nmap.org/) (network layer) and [OWASP ZAP](https://www.zaproxy.org/)
> (web layer), normalizes every result into one schema, enriches it with
> CVSS/CVE/EPSS, filters false positives, and emits prioritized **HTML / JSON /
> SARIF** reports with a CI gate.

**Detection and reporting only.** vulnpipe wraps existing scanners and reports
their findings for remediation. It contains no exploit code and emits no attack
payloads.

> [!WARNING]
> **Authorization notice — scan only systems you own or are explicitly permitted
> to test.** Active scanning is intrusive and, run against systems you are not
> authorized to test, is very likely illegal. vulnpipe enforces this: every scan
> requires the `--authorized` acknowledgement *and* a scope allowlist, and any
> target outside that scope is a hard error — nothing out of scope is ever
> scanned. See [`SECURITY.md`](SECURITY.md).

## Contents

- [See it in action](#see-it-in-action)
- [What it is](#what-it-is)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Install](#install)
- [Quickstart](#quickstart)
- [Configuration](#configuration)
- [Run a scan](#run-a-scan)
- [Reports](#reports)
- [CI usage: baseline, diff, gate](#ci-usage-baseline-diff-gate)
- [Run via Docker](#run-via-docker)
- [CLI reference](#cli-reference)
- [Development](#development)
- [License](#license)

## See it in action

- 📊 **[Live sample report](https://connor-p-mccune.github.io/vulnpipe/)** — real
  vulnpipe HTML output rendered in your browser, no install required.
- 🧪 **[Lab case study](docs/case-study.md)** — scanning OWASP Juice Shop end-to-end
  in a self-contained Docker lab, from `docker compose up` to a prioritized report.
- 🧠 **[Design decisions](docs/DECISIONS.md)** — the architecture trade-offs (stable
  fingerprints, immutable findings, pure transforms, bounded concurrency) behind it.

> Prefer a terminal demo? Generate one locally with
> [`vhs`](https://github.com/charmbracelet/vhs): `vhs assets/demo.tape` → `assets/demo.gif`.

## What it is

Point vulnpipe at an authorized, in-scope range and it will:

- **discover** the network surface with Nmap — open ports, services, product and
  version detection, OS guesses, and CVE-tagged findings from the `vulners` / `vuln`
  NSE scripts;
- **scan** the web services it finds (or URLs you declare) with a running OWASP ZAP
  daemon — spider + active scan, with optional authenticated sessions;
- **normalize** everything into a single `Finding` model with a stable fingerprint;
- **enrich** findings with CVSS scores/vectors (NVD), EPSS exploit-probability, and
  CISA **KEV** (known-exploited-in-the-wild) status — cached on disk, and never
  fabricated (a failed lookup leaves the field unknown);
- **filter** false positives via an allowlist plus a confidence threshold;
- **prioritize** by severity → CVSS → EPSS → asset criticality;
- **report** to JSON (canonical), HTML (human), and SARIF (the GitHub Security tab);
- **gate** CI by diffing against a baseline and failing only on *new* severe findings.

## How it works

Stages run in order; each scanner returns `list[Finding]`, and everything
downstream operates on that one model.

```mermaid
flowchart LR
    intake([intake]) --> nmap[nmap scan]
    intake --> zap[zap scan]
    nmap --> enrich[enrich<br/>CVSS · NVD · EPSS]
    zap --> enrich
    enrich --> norm[normalize] --> dedup[dedup] --> fp[false-positive<br/>filter] --> prio[prioritize]
    prio --> report[report<br/>JSON · HTML · SARIF]
    report --> diff[CI diff<br/>vs baseline] --> gate{gate}
    gate -->|new severe finding| fail([exit non-zero])
    gate -->|clean| ok([exit 0])
```

```
vulnpipe/
├── core/         models.py, config.py, orchestrator.py, logging.py
├── scanners/     base.py, nmap_scanner.py, zap_scanner.py, registry.py
├── enrichment/   cvss.py, nvd_client.py, epss_client.py
├── processing/   normalizer.py, deduplicator.py, false_positive.py, prioritizer.py
├── reporting/    json_reporter.py, html_reporter.py, sarif_reporter.py, templates/
├── ci/           baseline.py, differ.py, gate.py, junit.py
├── auth/         auth_contexts.py
└── cli/          main.py
```

The full design — module responsibilities, the finding lifecycle, fingerprinting,
and the diff/gate model — is in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Requirements

- **Python 3.12+**
- The **`nmap`** binary on `PATH` (for the network layer)
- A running **OWASP ZAP daemon** (for the web layer) — easiest via the bundled
  [Docker stack](#run-via-docker)
- Optional: an **NVD API key** (raises enrichment rate limits)

The network and web layers are independent: with no ZAP daemon you still get the
Nmap layer (and vice versa). A scanner that cannot run degrades to a logged warning
and an empty result rather than crashing the pipeline.

## Install

vulnpipe installs from source and exposes a `vulnpipe` console script.

```bash
git clone https://github.com/connor-p-mccune/vulnpipe.git
cd vulnpipe

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install .                      # runtime install
# or, for development (tests + linters + type checker):
pip install -e ".[dev]"
```

Verify it:

```console
$ vulnpipe version
vulnpipe 0.1.0
```

## Quickstart

**Try it in 60 seconds — no scanners, no services.** Render the bundled sample
report (real fixture-derived findings) to a self-contained HTML file:

```bash
pip install -e .
vulnpipe report --input examples/sample-report.json --format html > report.html
# open report.html in a browser — or see the live version linked above
```

**Run a real scan** (needs the `nmap` binary and/or a ZAP daemon — see [Requirements](#requirements)):

```bash
# 1. Create your scope/targets file (gitignored) from the example and edit it.
cp configs/targets.example.yaml configs/targets.yaml

# 2. Put secrets in the environment (never in the config file).
cp .env.example .env               # then edit, and: source .env

# 3. Run an authorized scan; write JSON + HTML + SARIF into ./results.
vulnpipe scan \
  --config configs/targets.yaml \
  --authorized \
  --output results \
  --html results/report.html \
  --sarif results/vulnpipe.sarif
```

`scan` refuses to start without `--authorized` and a non-empty scope allowlist, and
refuses any target outside that scope.

## Configuration

vulnpipe reads a single YAML **targets/scope file**. Copy the annotated example and
edit it:

```bash
cp configs/targets.example.yaml configs/targets.yaml   # gitignored
```

- [`configs/targets.example.yaml`](configs/targets.example.yaml) — the scope, the
  targets, optional per-target authentication, and all scanner/pipeline settings
  (every setting is optional and shown with its default).
- [`configs/default.yaml`](configs/default.yaml) — documents the scanner/pipeline
  **defaults** only (it deliberately omits `scope` and `targets`, which are
  required and live in your targets file).
- [`configs/false_positives.example.yaml`](configs/false_positives.example.yaml) —
  an optional allowlist that suppresses known-benign findings and sets a minimum
  confidence threshold; pass it with `--false-positives`.

### Scope (the authorization allowlist)

Nothing outside `scope` is ever scanned.

```yaml
scope:
  hosts:
    - "10.0.0.0/24"           # IPs and CIDRs (network scope)
    - "*.lab.example.com"     # wildcard hostname (also matches lab.example.com)
  urls:
    - "https://app.lab.example.com"   # full http(s) URL prefixes (web scope)
```

### Targets

Each target is a network host/CIDR (handed to Nmap), one or more web URLs (handed
to ZAP), or both. Every target must fall inside `scope`.

```yaml
targets:
  - name: internal-net
    host: "10.0.0.0/24"           # network-only

  - name: web-app
    host: "10.0.0.10"
    urls:
      - "https://app.lab.example.com"
```

### Authenticated scanning (optional, recommended)

Authenticated scans are the biggest false-positive reducer — without a session ZAP
reports spurious 401/redirect findings. A target may carry an `auth` block;
**credentials are referenced by environment-variable name and resolved at scan time,
never stored inline.** Three schemes are supported (`form`, `header`/JWT bearer, and
`script`):

```yaml
  - name: web-app
    host: "10.0.0.10"
    urls: ["https://app.lab.example.com"]
    auth:
      type: form
      login_url: "https://app.lab.example.com/login"
      username_field: "email"
      password_field: "password"
      username_env: "APP_USERNAME"   # value read from $APP_USERNAME at scan time
      password_env: "APP_PASSWORD"
      logged_in_indicator: "Log out"
```

### Secrets

Secrets never live in the config file — only the *name* of the environment variable
does. Provide them via the environment or a gitignored `.env` (see
[`.env.example`](.env.example)):

| Variable | Purpose |
| --- | --- |
| `ZAP_API_KEY` | ZAP daemon API key (must match the daemon's configured key). |
| `ZAP_API_URL` | ZAP daemon base URL (default `http://localhost:8080`). |
| `NVD_API_KEY` | Optional NVD key; raises enrichment rate limits. |
| `APP_USERNAME` / `APP_PASSWORD` | Form/script authenticated-scan credentials. |
| `API_BEARER_TOKEN` | Bearer/JWT token for header-based authenticated scanning. |

### Scanner, pipeline, and prioritization settings

The targets file also accepts optional `nmap`, `zap`, `enrichment`, `run`, and
`prioritization` blocks (all with sane defaults — see the example). For example,
`prioritization` ranks findings on more business-critical assets higher:

```yaml
prioritization:
  default_criticality: medium     # one of: low, medium, high, critical
  assets:
    - host: "10.0.0.10"           # the web-app host is business-critical
      criticality: critical
```

## Run a scan

```bash
vulnpipe scan --config configs/targets.yaml --authorized
```

This runs the full pipeline and writes the canonical report to
`results/latest.json`. Add `--html`, `--sarif`, and/or `--junit` to also write those
formats, `--baseline baseline.json` to diff and gate against a baseline, and
`--gate-severity` to set the gate threshold (default `high`).

A run logs a concise summary:

```text
[12:00:00] INFO   authorization confirmed; scanning 2 target(s) in scope
[12:00:42] INFO   nmap scan complete findings=11 partial=False targets=1
[12:01:55] INFO   zap scan complete failed=0 findings=6 targets=1
[12:01:56] INFO   wrote findings JSON: results/latest.json
[12:01:56] INFO   findings: 15 (critical=1, high=5, medium=2, low=2, informational=5)
[12:01:56] INFO   diff: new=15 persisting=0 resolved=0
[12:01:56] ERROR  gate failed: 6 new finding(s) at or above high
```

> On the **first** run there is no baseline, so every finding is "new" and the gate
> may fail by design. Establish a baseline (below) so CI gates only on *regressions*.

## Reports

vulnpipe renders three formats from the same findings; all are **deterministic** for
fixed input (no embedded wall-clock timestamp), so report output and snapshot tests
are stable across runs.

| Format | Use |
| --- | --- |
| **JSON** | The canonical, lossless artifact. `scan` writes `results/latest.json`; `report` / `diff` / `baseline` read it back. |
| **HTML** | The human-readable report: summary, inline SVG severity chart, per-host breakdown, and a client-side sortable findings table. |
| **SARIF** | SARIF 2.1.0 for the GitHub code-scanning / Security tab. |

Render any format from a findings JSON to stdout:

```bash
vulnpipe report --input results/latest.json --format html  > report.html
vulnpipe report --input results/latest.json --format sarif > vulnpipe.sarif
```

### Sample report

A ready-made sample (rendered from the project's test fixtures, so it contains only
synthetic lab data) lives in [`examples/`](examples/):

- [`examples/sample-report.html`](examples/sample-report.html) — open it in a browser
- [`examples/sample-report.json`](examples/sample-report.json) — the canonical JSON

It holds 15 findings across 4 hosts, in vulnpipe's prioritized order:

```text
SEVERITY      CVSS  SOURCE  HOST                  TITLE
critical       9.8  nmap    10.0.0.5              CVE-2021-42013
high           7.7  nmap    10.0.0.6              CVE-2021-23017
high           7.5  nmap    10.0.0.5              CVE-2016-10009
high           7.5  nmap    10.0.0.5              CVE-2021-41773
high            –   zap     app.lab.example.com   SQL Injection
high            –   zap     app.lab.example.com   Cross Site Scripting (Reflected)
medium         5.3  nmap    10.0.0.5              CVE-2018-15473
medium          –   zap     app.lab.example.com   Vulnerable JS Library
low             –   zap     app.lab.example.com   Application Error Disclosure
…
```

The canonical JSON is an envelope of `schema_version`, tool identity, a summary, and
every finding with its fingerprint:

```jsonc
{
  "schema_version": "1.0",
  "tool": { "name": "vulnpipe", "version": "0.1.0" },
  "summary": {
    "total": 15,
    "hosts": 4,
    "by_severity": { "critical": 1, "high": 5, "medium": 2, "low": 2, "informational": 5 }
  },
  "findings": [
    {
      "source": "nmap",
      "host": "10.0.0.5",
      "title": "CVE-2021-42013",
      "severity": "critical",
      "port": 80,
      "plugin_id": "vulners",
      "cve_ids": ["CVE-2021-42013"],
      "cvss_score": 9.8,
      "fingerprint": "741786901e8421ee…"
    }
    // …
  ]
}
```

## CI usage: baseline, diff, gate

vulnpipe turns findings into a build verdict by comparing the current scan against a
stored **baseline** of accepted findings (matched by fingerprint):

- **new** — in the scan but not the baseline;
- **persisting** — in both (baselined, so exempt from the gate);
- **resolved** — in the baseline but gone from the scan.

The **gate** fails the build only when a *new* finding meets or exceeds the
configured severity (default `high`), so existing accepted issues don't break CI —
only regressions do.

```bash
# Establish a baseline from an accepted scan.
vulnpipe baseline --input results/latest.json --output baseline.json

# Later, diff a new scan against it.
vulnpipe diff --baseline baseline.json --current results/latest.json
```

```console
$ vulnpipe diff --baseline baseline.json --current results/latest.json
new:        2
persisting: 12
resolved:   1
  + [critical] CVE-2021-42013 (10.0.0.5)
  + [high] SQL Injection (app.lab.example.com)
  - [low] Application Error Disclosure (app.lab.example.com)
```

Run the gate inside `scan` by passing the baseline; it exits non-zero when a new
finding trips the threshold (use `--no-gate` to report without failing):

```bash
vulnpipe scan -c configs/targets.yaml --authorized \
  --baseline baseline.json --gate-severity high \
  --sarif results/vulnpipe.sarif --junit results/junit.xml
```

A ready-to-adapt GitHub Actions workflow lives at
[`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml): it
runs an authorized scan, uploads the SARIF to code scanning, publishes the JUnit
gate report, and carries the baseline forward across runs via the Actions cache.

## Run via Docker

The bundled compose stack brings up an OWASP ZAP daemon and the scanner on a shared
network and runs an authorized scan end to end — one command:

```bash
# 1. Create your in-scope targets file and provide secrets.
cp configs/targets.example.yaml configs/targets.yaml   # then edit
cp .env.example .env                                    # set ZAP_API_KEY, etc.

# 2. Bring up ZAP + the scanner and run the scan.
ZAP_API_KEY=changeme docker compose -f docker/docker-compose.yml up --build
```

The scanner reaches ZAP at `http://zap:8080` over the shared network (the example
config picks that up from `${ZAP_API_URL}`, which compose sets), and reports land in
the `vulnpipe-results` volume. The image is multi-stage and runs as an unprivileged
user; without `NET_RAW`, Nmap uses TCP connect scans. See the
[Docker packaging](docs/ARCHITECTURE.md#docker-packaging) notes for details.

## CLI reference

```text
vulnpipe [--verbose/-v] COMMAND [OPTIONS]
```

| Command | What it does |
| --- | --- |
| `scan` | Validate authorization/scope, run the pipeline, write reports, and gate. Requires `--config` and `--authorized`. |
| `report` | Render a findings JSON into JSON / HTML / SARIF on stdout (`--input`, `--format`). |
| `diff` | Classify current findings against a baseline as new / persisting / resolved (`--baseline`, `--current`, `--format text\|json`). |
| `baseline` | Create or update a baseline from a findings JSON (`--input`, `--output`, `--update`). |
| `version` | Print the vulnpipe version. |

Run `vulnpipe <command> --help` for the full option list.

## Development

```bash
pip install -e ".[dev]"
pre-commit install
```

A change is "done" only when all four quality gates pass:

```bash
ruff check .          # lint
black --check .       # formatting
mypy vulnpipe         # type checking (strict)
pytest                # unit tests (no network, no real scanners)
pytest -m integration # integration tests (need real scanners)
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the conventions, testing rules, and how
to add a new scanner or reporter.

## License

Licensed under the [Apache License 2.0](LICENSE).
