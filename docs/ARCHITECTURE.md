# vulnpipe architecture

Detailed design and architecture notes for vulnpipe — the longer-form companion
to the README.

## Goal

Orchestrate existing scanners (Nmap for the network layer, OWASP ZAP for the web
layer), normalize their output into a single model, enrich it, filter noise, and
emit prioritized reports with a CI gate. **Detection and reporting only** — the
project wraps scanners and reports findings for remediation. It contains no
exploit code.

## Pipeline stages

Stages run in order; each scanner returns `list[Finding]`, and everything
downstream operates on that one model.

```
intake → nmap scan → zap scan → enrich (cvss/nvd/epss)
       → normalize → dedup → false-positive filter → prioritize
       → report (json/html/sarif) → ci diff vs baseline → gate
```

1. **intake** — load and validate the YAML config (`core/config.py`); enforce the
   authorization acknowledgement and the scope allowlist before anything runs.
2. **nmap scan** (`scanners/nmap_scanner.py`) — run `nmap` over the in-scope
   range with XML to stdout (`-oX -`); parse open ports, services, OS guesses,
   and `vulners`/`vuln` NSE CVE output.
3. **zap scan** (`scanners/zap_scanner.py`) — drive a running ZAP daemon's spider
   + active scan over in-scope web services and pull `core.alerts`.
4. **enrich** (`enrichment/`) — CVSS scoring, NVD CVE metadata, EPSS probabilities
   (HTTP cached on disk; failures mark fields unknown, never guessed).
5. **normalize / dedup / false-positive / prioritize** (`processing/`) — pure
   functions transforming findings: normalize cleans and builds them, dedup
   collapses duplicates by fingerprint (keeping the richest detail from each
   group), the false-positive filter drops allowlisted findings and any below a
   confidence floor (`configs/false_positives.example.yaml`), and prioritization
   orders by severity, then CVSS, then EPSS, then asset criticality.
6. **report** (`reporting/`) — JSON (canonical), HTML (human), SARIF (CI/dashboards).
7. **ci diff + gate** (`ci/`) — diff against a baseline (new / persisting /
   resolved) and decide the exit status from a severity policy.

The orchestrator (`core/orchestrator.py`) runs the network layer through a bounded
thread pool and caps ZAP concurrency separately (active scans are heavy).

## The `Finding` model

Defined in `core/models.py` (pydantic v2, frozen). Every scanner emits `Finding`
objects through `processing/normalizer.py` helpers so conventions stay uniform.

A finding carries a stable **fingerprint**:

```
sha256(host | port | source | plugin_or_alert_id | normalized_title)
```

It must be stable across runs for the same underlying issue — this is what the
deduplicator and the CI differ rely on. Findings are immutable; enrichment and
processing produce new findings via `model_copy`, leaving the fingerprint intact.

`Severity` and `Confidence` are ordered enums (`.rank`). `Severity.from_cvss_score`
applies the FIRST CVSS v3 qualitative bands.

## Reporting

Reporters (`reporting/`) each subclass `BaseReporter` and turn `list[Finding]` into
a serialized string. All three are **deterministic for fixed input** — findings are
emitted in the order given (the prioritized order), enum/severity ordering is fixed,
and no wall-clock timestamp is embedded — so report output and snapshot tests are
stable across runs. Shared, pure view-model helpers (`reporting/summary.py`) compute
the severity/host counts once so the formats cannot drift.

- **JSON** (`json_reporter.py`) is the canonical, lossless artifact: an envelope of
  `schema_version`, tool identity, a summary, and every finding serialized with its
  fingerprint. It round-trips — `build_report` → JSON → `report_to_findings`
  reproduces the findings exactly (the computed fingerprint is stripped before
  re-validation and recomputed identically) — so the HTML/SARIF renderers and the CI
  differ read it back rather than re-running scanners.
- **HTML** (`html_reporter.py` + Jinja2 templates) renders a summary with severity
  counts, an inline SVG severity chart (bar geometry computed by a pure, tested
  helper), a per-host breakdown, and a client-side sortable findings table.
  Autoescaping is on, so scanner evidence such as a reflected `<script>` payload is
  shown as inert text, never live markup.
- **SARIF** (`sarif_reporter.py`) emits SARIF 2.1.0 for the GitHub Security tab: one
  rule per distinct check, severity mapped to `level`, the finding fingerprint under
  `partialFingerprints` for stable cross-run tracking, and a `security-severity`
  ranking hint (the real CVSS score when known, otherwise the severity band floor —
  never written back onto the finding).

`get_reporter(fmt)` resolves a format name to a reporter; the `report` CLI command
loads a findings JSON and renders it to any format on stdout.

## Authenticated scanning

Authenticated scans are the biggest false-positive reducer — without a session ZAP
reports spurious 401/redirect findings. `auth/auth_contexts.py` supports three ZAP
schemes (form, header/JWT bearer, script) and is split like the rest of the codebase:

- `build_auth_context(auth)` is **pure** (config in, resolved context out). It pulls
  credentials from the environment via `resolve_secret`, so a missing credential is a
  clear error and no secret is ever read from the config file. This is what "builds
  from config" with no live ZAP.
- `apply_auth_context(client, context_id, ctx)` performs the ZAP API calls — auth
  method, cookie-based session management, logged-in/out indicators, and (for the
  credentialed schemes) an enabled ZAP user. Header/bearer auth needs no user: the
  token is injected on every request via a Replacer rule.

The ZAP scanner wires this in per target: `select_web_targets_with_auth` carries each
URL's `auth` block, and when one is present the spider and active scan run *as the
authenticated user* (`scan_as_user`). An auth-setup failure degrades to a logged
warning and an unauthenticated scan rather than aborting the target. Resolved
credentials live only on the transient context during a scan — never logged,
serialized, or written back into the config model.

## CI integration

After reporting, the CI stage (`ci/`) turns findings into a build verdict.

- **Baseline** (`baseline.py`) records the accepted findings keyed by fingerprint,
  with a small metadata snapshot (source, host, port, title, severity) per entry —
  enough to recognize a finding across runs and to describe one that later resolves.
  The on-disk form is deterministic (entries in fingerprint order, no timestamp), so
  `save_baseline` → `load_baseline` round-trips exactly. Build one with
  `build_baseline`; extend an existing one with `merge_baseline`.
- **Differ** (`differ.py`) classifies the current findings against a baseline by
  fingerprint: **new** (absent from the baseline), **persisting** (present), and
  **resolved** (in the baseline but gone from the scan). `new` / `persisting` keep the
  prioritized order; `resolved` follows the baseline order, so the diff is deterministic.
- **Gate** (`gate.py`) fails the build when any **new** finding meets or exceeds a
  configured severity (High by default). Persisting (baselined) findings are exempt —
  that is the whole point of a baseline. The verdict is exposed as a process
  `exit_code` so a CI job exits non-zero exactly when a regression is introduced.
- **JUnit** (`junit.py`) renders the verdict as JUnit XML: every current finding is a
  `<testcase>` and each gate-triggering finding a `<failure>`, with all content
  XML-escaped. Together with the SARIF report (reused from `reporting/`) this feeds CI
  dashboards and the GitHub Security tab.

`.github/workflows/security-scan.yml` is an example workflow: it runs an authorized
scan, uploads the SARIF to code scanning, and fails the job on a new High/Critical
finding while still publishing the JSON / SARIF / JUnit artifacts.

## Orchestration & CLI

The orchestrator (`core/orchestrator.py`) runs the whole pipeline and returns the
prioritized findings plus the diff and gate verdict (`run_pipeline` →
`PipelineResult`); rendering and persisting reports is the CLI's job. It enforces the
authorization and scope hard rules before any scanner runs — defense in depth, in
addition to the CLI's own gate.

Stages and concurrency: the network layer runs Nmap once over the in-scope range
(Nmap handles a 200+ host range natively, so it needs no application-level fan-out).
The HTTP/HTTPS services it discovers are turned into URLs (`derive_web_targets`) and,
together with URLs declared in config, handed to the web layer. The web layer is
fanned out across a **bounded thread pool** (`run.max_workers`), with ZAP active-scan
concurrency **capped separately** (`zap.max_concurrency`) via a semaphore, because
active scans are resource-heavy. The combined findings then flow through enrich →
dedup → false-positive filter → prioritize → diff → gate. Scanners are resolved by
name through the registry and never special-cased; the per-layer scan callables are
injectable so the pipeline is testable without real tools.

The CLI (`cli/main.py`, Typer) exposes four commands:

- `scan` — the authorization gate: it requires `--authorized` plus an in-scope scope
  file, runs the pipeline, writes the canonical JSON report (and optional SARIF / HTML
  / JUnit), and exits non-zero when the gate trips on a newly introduced severe
  finding. Reports are written *before* the gate exit, so CI can still upload them.
- `report` — render a findings JSON to JSON / HTML / SARIF on stdout.
- `diff` — classify a findings JSON against a baseline (text or JSON output).
- `baseline` — create or update a baseline from a findings JSON.

## Extension points

- **New scanner:** subclass `BaseScanner`, implement `scan() -> list[Finding]`,
  and register it via `scanners/registry.py`. Do not special-case scanners in the
  orchestrator.
- **New reporter:** subclass `BaseReporter`, implement `render()`, and register it in
  `reporting/__init__.py` so `get_reporter` can resolve it.

## Hard rules (non-negotiable)

1. **Authorization scope.** Only hosts/URLs in the scope allowlist are scanned.
   The orchestrator refuses out-of-scope targets and requires `--authorized` plus
   a scope file before any scan (`ensure_authorized`, `ensure_target_in_scope`).
2. **Detection only.** No exploit payloads, code-execution chains, or malware.
3. **No fabricated data.** Findings trace to real scanner output or real NVD/EPSS
   lookups; failed enrichment is marked unknown, never invented.
4. **No secrets in the repo.** Credentials and API keys come from the environment
   / a gitignored `.env`, referenced by variable name from config.

## Configuration & secrets

`core/config.py` loads YAML, substitutes `${ENV_VAR}` references, and validates a
strict schema (`Scope`, `Target`, the discriminated `AuthConfig`, and scanner
settings). Secrets are referenced by environment-variable *name* and resolved at
scan time with `resolve_secret`, so raw credentials never enter the config file or
the in-memory model.

Asset criticality for prioritization is configured under `prioritization`: each
rule maps a host / CIDR / `*.domain` pattern to a criticality, resolved per finding
with `PrioritizationConfig.criticality_for` (first matching rule wins, else the
configured default). The prioritizer takes that resolver as an argument, keeping
`processing/` decoupled from config loading.
