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
4. **enrich** (`enrichment/`) — CVSS scoring, NVD CVE metadata, EPSS probabilities,
   and CISA KEV (known-exploited) cross-referencing (HTTP cached on disk; failures
   mark fields unknown, never guessed).
5. **normalize / dedup / false-positive / prioritize** (`processing/`) — pure
   functions transforming findings: normalize cleans and builds them, dedup
   collapses duplicates by fingerprint (keeping the richest detail from each
   group), the false-positive filter drops allowlisted findings and any below a
   confidence floor (`configs/false_positives.example.yaml`), and prioritization
   orders by severity, then known-exploited (KEV) status, then CVSS, then EPSS, then
   asset criticality.
6. **report** (`reporting/`) — JSON (canonical), HTML (human), SARIF (CI/dashboards),
   OpenVEX (exploitability exchange).
7. **ci diff + gate** (`ci/`) — diff against a baseline (new / persisting /
   resolved) and decide the exit status from a severity policy.

The orchestrator (`core/orchestrator.py`) runs the network layer through a bounded
thread pool and caps ZAP concurrency separately (active scans are heavy).

## Module responsibilities

| Package / module | Responsibility |
| --- | --- |
| `core/models.py` | The shared `Finding`, `Host`, and `Service` models, the `Severity` / `Confidence` / `AssetCriticality` enums, and the `compute_fingerprint` helper. |
| `core/standards.py` | Curated OWASP Top 10 2021 / CWE Top 25 reference data and pure CWE-to-category lookups (unmapped CWEs return no category, never a guess). |
| `core/config.py` | YAML + environment config loading, the strict pydantic schema, and the authorization/scope guards (`ensure_authorized`, `ensure_*_in_scope`). |
| `core/orchestrator.py` | Runs the full pipeline end to end and returns the prioritized findings plus the diff and gate verdict. |
| `core/logging.py` | The rich-backed structured logger used throughout (the project never uses `print`). |
| `scanners/` | `BaseScanner` + the registry, and the Nmap (network), ZAP (web), and Nuclei (template-based) integrations. Each `scan()` returns `list[Finding]`. |
| `enrichment/` | CVSS parsing/scoring, cached NVD / EPSS lookups, and CISA KEV cross-referencing that fill — never fabricate — the `cvss_*` / `epss_*` / `kev` fields. |
| `processing/` | Pure finding transforms: normalize, dedup, false-positive filter, prioritize, and ownership annotation (stamp operator-declared owner/tags for triage routing). |
| `reporting/` | The JSON / HTML / Markdown / CSV / Prometheus / SARIF / GitLab / OpenVEX / CycloneDX renderers, the remediation planner, the terminal `stats` view, and the shared summary view-model. Deterministic for fixed input. |
| `ci/` | The baseline store, the differ, the severity gate, the policy-as-code gate (`policy.py`), JUnit XML output, and multi-scan trend analysis. |
| `sbom/` | Supply-chain analysis: CycloneDX parsing, the OSV.dev advisory client, and the analyzer that normalizes advisories into findings. Passive (reads a file, queries a public API); never probes the described software. |
| `ingest/` | Importers that normalize third-party scanner reports (Trivy, Grype) into the shared `Finding` model. Pure `dict → list[Finding]` parsers, passive (read a local report, map it), routed by name through a small registry. |
| `auth/` | ZAP authentication-context construction (form / header-JWT / script). |
| `server/` | A dependency-free, read-only HTTP view over a findings report (`serve`): a pure `path → Response` router plus a thin `http.server` socket adapter. Renders through the existing reporters; never scans. |
| `cli/main.py` | The Typer CLI (`scan` / `report` / `serve` / `diff` / `baseline` / …) and the `--authorized` + scope gate. |

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

### Composite risk score

Every finding also exposes a computed `risk_score` (0–100) — a single, transparent
number that blends **impact** and **likelihood** so reports can rank issues by
real-world urgency, not severity alone:

- **impact** is the CVSS base score (`cvss_score / 10`) when known, else a
  per-severity fallback (so an unscored finding still gets a number);
- **likelihood** is `1.0` when the CVE is in the CISA KEV catalog (actively
  exploited), else the EPSS probability, else `0.0` — a conservative floor.

Likelihood modulates impact between a 0.7 base weight and full weight
(`compute_risk_score`), so a serious-but-unexploited issue still scores within its
band while active exploitation pushes it to the top. Like the fingerprint, it is
computed and output-only: it appears in every report format but is stripped on JSON
round-trip and never feeds the fingerprint. Nothing is fabricated — it is a
documented function of fields already on the finding, not a new data source.

### Lifecycle of a finding

A finding is created once, in a scanner, and from then on is only ever *copied* —
its fingerprint never changes from birth to report:

1. **born** — a scanner maps raw tool output into a `Finding` through
   `processing/normalizer.make_finding` (text trimmed, CVE ids validated, severity
   derived from the CVSS score when not supplied). `source` records the tool.
2. **enriched** — `enrichment/` looks up each cited CVE once and fills only the
   still-unknown `cvss_*` / `epss_*` fields via `model_copy`, and flags findings whose
   CVE is in the CISA KEV catalog (`kev=True`, with catalog context in metadata); data
   a scanner already provided is never overwritten and a failed lookup leaves the field
   `None` (or `kev=False` — absence of evidence, not a guess).
3. **deduplicated** — findings sharing a fingerprint are merged into the single
   richest finding (`processing/deduplicator`).
4. **filtered** — the false-positive stage drops allowlisted findings and anything
   below the configured confidence floor. Allowlist entries are time-boxable risk
   acceptances (optional `reason` + inclusive `expires` date, evaluated against an
   injectable date so tests stay pinned); a lapsed entry stops suppressing and the
   orchestrator warns about it, so the finding resurfaces rather than staying
   silently accepted forever.
5. **prioritized** — the survivors are ordered most-actionable-first
   (severity → CVSS → EPSS → asset criticality → fingerprint).
6. **reported** — emitted to JSON / HTML / SARIF in that prioritized order.
7. **diffed** — the fingerprint is matched against the baseline to classify the
   finding as new / persisting / resolved, which the gate turns into a build verdict.

Because the model is `frozen` and every stage returns new findings rather than
mutating, one underlying issue keeps a single stable identity across the whole run
(and across runs) — exactly what dedup and the differ rely on.

## Reporting

Reporters (`reporting/`) each subclass `BaseReporter` and turn `list[Finding]` into
a serialized string. All are **deterministic for fixed input** — findings are
emitted in the order given (the prioritized order), enum/severity ordering is fixed,
and no wall-clock timestamp is embedded — so report output and snapshot tests are
stable across runs. (The OpenVEX publication timestamp is the one spec-mandated
exception; see its bullet below.) Shared, pure view-model helpers
(`reporting/summary.py`) compute the severity/host counts once so the formats
cannot drift.

- **JSON** (`json_reporter.py`) is the canonical, lossless artifact: an envelope of
  `schema_version`, tool identity, a summary, and every finding serialized with its
  fingerprint. It round-trips — `build_report` → JSON → `report_to_findings`
  reproduces the findings exactly (the computed fingerprint is stripped before
  re-validation and recomputed identically) — so the HTML/SARIF renderers and the CI
  differ read it back rather than re-running scanners.
- **HTML** (`html_reporter.py` + Jinja2 templates) renders a summary with severity
  counts and a known-exploited (KEV) count, an inline SVG severity chart (bar
  geometry computed by a pure, tested helper), a per-host breakdown that highlights
  known-exploited findings, and a client-side **filterable** (search + severity +
  KEV-only) and sortable findings table with risk-score and KEV columns. Autoescaping
  is on, so scanner evidence such as a reflected `<script>` payload is shown as inert
  text, never live markup.
- **SARIF** (`sarif_reporter.py`) emits SARIF 2.1.0 for the GitHub Security tab: one
  rule per distinct check, severity mapped to `level`, the finding fingerprint under
  `partialFingerprints` for stable cross-run tracking, a `security-severity` ranking
  hint (the real CVSS score when known, otherwise the severity band floor — never
  written back onto the finding), and the composite `riskScore` plus a `kev` flag in
  each result's properties so those signals travel to SARIF consumers too.
- **GitLab** (`gitlab_reporter.py`) emits a GitLab-compatible security report for the
  GitLab Vulnerability Report and the merge-request security widget — the other half
  of the "surfaces natively in your CI platform" story SARIF starts. vulnpipe is a
  dynamic scanner, so it exports a DAST-style report: the vulnerability `id` is the
  stable fingerprint (GitLab tracks the same issue across pipelines), `identifiers`
  carry the real CVEs/CWEs plus a vulnpipe rule id so the list is never empty, and
  severity maps onto GitLab's vocabulary. The schema-required `scan.start_time` /
  `end_time` are the one non-derivable field: the pure builder omits them (so snapshot
  tests stay stable) while the reporter stamps them, honoring `SOURCE_DATE_EPOCH` —
  the same reproducibility handling the OpenVEX timestamp gets.
- **OpenVEX** (`vex_reporter.py`) emits an [OpenVEX](https://openvex.dev) 0.2.0
  document for exploitability-exchange tooling. A statement is produced only for a
  finding that cites a real vulnerability identifier — a CVE, or a GHSA/OSV id from
  the SBOM layer — and only with the `affected` status: `not_affected` / `fixed`
  are human exploitability judgements the pipeline never fabricates. Statements
  group by `(vulnerability, action)` with sorted products (a purl for SBOM
  findings, `host[:port]` for network/web ones), KEV listings surface in
  `status_notes`, and the document `@id` is content-addressed. The spec-required
  publication `timestamp` is the one non-derivable field: the pure
  `build_vex`/`render_vex` functions omit it unless given one, while the registered
  reporter stamps real UTC time, honoring `SOURCE_DATE_EPOCH` (the
  reproducible-builds convention) so CI can emit byte-identical documents.
- **CycloneDX** (`cyclonedx_reporter.py`) emits a
  [CycloneDX](https://cyclonedx.org) 1.5 vulnerability report (VDR) — the other
  half of the SBOM loop: vulnpipe reads a CycloneDX SBOM and now writes a CycloneDX
  BOM whose `vulnerabilities` link each detected issue to the component it affects
  (a `library` keyed by purl for supply-chain findings, an `application` keyed by
  `host[:port]` for network/web ones). Like the OpenVEX reporter it is honest by
  construction: only findings that cite a real identifier produce an entry, no
  `analysis` triage state is fabricated (making it a disclosure report, not a full
  VEX), and a rating carries the real qualitative severity always but a numeric
  score only when a real CVSS is known. Findings sharing an identifier collapse into
  one vulnerability with several `affects`. The `serialNumber` is content-addressed
  and the `metadata.timestamp` is the one non-derivable field (the pure builder omits
  it; the reporter stamps it, honoring `SOURCE_DATE_EPOCH`).

`get_reporter(fmt)` resolves a format name to a reporter; the `report` CLI command
loads a findings JSON and renders it to any format on stdout.

### Standards mapping (OWASP Top 10 / CWE Top 25)

`core/standards.py` holds a curated copy of the official OWASP Top 10 2021 CWE
mapping and the 2023 CWE Top 25 list -- pure reference data plus pure lookups. The
shared view-model (`reporting/summary.summarize_standards`) distributes findings
over those frameworks once, and every format surfaces it: the HTML report gets a
ranked OWASP bar chart (most-prevalent weakness class first, pure SVG geometry
from `build_owasp_chart`), a CWE Top 25 card, and an OWASP column; Markdown and the
terminal `stats` view get an OWASP table; CSV gets an `owasp` column; SARIF rules
carry `external/owasp/...` tags next to the CWE tags. The mapping is
presentation-layer only -- it never enters the finding model or the canonical
JSON, and a finding whose CWEs are absent from the curated map is reported as
*unmapped* rather than forced into a category.

### Status badge

`reporting/badge.py` renders findings into a flat shields-style SVG
(`vulnpipe badge`): the value lists the two worst non-empty severity bands (or
``clean``), the color follows the report palette, and a leading ``!`` flags
known-exploited findings. Deterministic like every renderer (fixed-width text
approximation, no timestamp) and XML-escaped throughout.

### Remediation planning

`reporting/remediation.py` turns a flat findings list into a short, ordered
*worklist*. `plan_remediations` (pure, deterministic) groups findings by the action
that resolves them — a dependency by its **package** (one upgrade), a network service
by **product-per-host** (one patch), everything else by **weakness class** across
endpoints — and ranks the groups by known-exploited status, then severity, then the
total composite risk each removes, then count. Each `RemediationAction` reuses the
scanner's own `solution` text when it exists and otherwise falls back to a template
that never invents a fixed version, so the plan stays honest. The same planner backs
`vulnpipe remediate` (text / JSON / Markdown), a "Remediation plan" panel in the HTML
report, and a "Top remediations" table in the terminal `stats` view — computed one
way so the executive "what to fix first" reads identically everywhere.

### Serving a report (dashboard & API)

`server/` exposes an already-computed findings JSON as a small local web service —
`vulnpipe serve` — so a report can be browsed and queried instead of only rendered
to a file. It is built on the standard-library `http.server` alone (no web-framework
dependency) and split for testability:

- `server/routes.py` is a **pure** `path → Response` router: `render_route` maps a
  request path onto a `Response` (status, content type, body) by delegating to the
  existing reporters, so it is exhaustively unit-testable without opening a socket
  and inherits their determinism. It serves the HTML report at `/`, a JSON REST API
  under `/api` (`/api/findings` = the canonical envelope, `/api/summary` = the stats
  payload, `/api/remediation` = the ranked plan, `/api` = a route index), Prometheus
  text at `/metrics`, and a `/healthz` liveness probe; an unknown path is a 404 that
  lists the routes.
- `server/http_server.py` is a thin socket adapter: `build_handler` captures an
  immutable snapshot of the findings so concurrent requests see a consistent view,
  and the handler only translates `GET`/`HEAD` into a response and writes headers.

It is **read-only** by construction — it renders an existing report and never scans,
mutates state, or reads a request body — so, like `report` and `stats`, it runs
outside the authorization/scope gate. Mutating verbs get a `405`, responses carry
`X-Content-Type-Options: nosniff` and `Cache-Control: no-store`, and it binds
loopback (`127.0.0.1`) by default; a non-loopback bind is honored but warned about,
since it publishes the report on the network.

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
  An optional `first_seen` date per entry (stamped by `baseline --track-age`, and
  preserved across merges so age is measured from a finding's true first appearance)
  powers the SLA layer; it is omitted from the on-disk form when unset, so an
  age-untracked baseline stays byte-identical to one written before the field
  existed. The on-disk form is deterministic (entries in fingerprint order, no
  timestamp), so `save_baseline` → `load_baseline` round-trips exactly. Build one
  with `build_baseline`; extend an existing one with `merge_baseline`.
- **Differ** (`differ.py`) classifies the current findings against a baseline by
  fingerprint: **new** (absent from the baseline), **persisting** (present), and
  **resolved** (in the baseline but gone from the scan). `new` / `persisting` keep the
  prioritized order; `resolved` follows the baseline order, so the diff is deterministic.
- **Gate** (`gate.py`) fails the build when any **new** finding meets or exceeds a
  configured severity (High by default) *or*, optionally, a composite risk-score
  threshold (`--gate-risk-score`), so an actively-exploited Medium can fail CI even
  though it sits below the severity bar. Persisting (baselined) findings are exempt —
  that is the whole point of a baseline. The verdict is exposed as a process
  `exit_code` so a CI job exits non-zero exactly when a regression is introduced.
- **Policy** (`policy.py`) generalizes the gate into policy-as-code: a reviewable
  YAML file (`configs/policy.example.yaml`) declaring per-severity budgets for new
  findings (`max_new`), a total-new cap, a risk-score threshold, and a block on new
  known-exploited (KEV) findings. `evaluate_policy` is pure over a diff and reports
  violations in a fixed rule order; `policy_from_threshold` expresses the plain
  severity gate as a policy so both forms share one evaluation path. Either verdict
  (`GateResult` or `PolicyResult`) satisfies the structural `GateVerdict` protocol
  the JUnit renderer and the CLI consume. `scan --policy` swaps the verdict in, and
  the standalone `gate` command re-evaluates a findings JSON without rescanning.
- **SLA** (`sla.py`) answers the complementary question the gate does not: has an
  *accepted* (baselined) finding stayed open past its remediation deadline? An
  `SlaPolicy` (`configs/sla.example.yaml`) declares per-severity budgets in days, and
  `evaluate_sla` — pure over the current findings, the baseline's `first_seen` dates,
  and an injected evaluation date — flags every finding older than its deadline,
  worst-severity then oldest first. A finding with no recorded first-seen date is
  *untracked* and never breaches (unknown age is never a violation). The `sla` command
  exposes it with a process `exit_code`, so CI can fail a build on lingering risk, not
  just newly introduced risk.
- **JUnit** (`junit.py`) renders the verdict as JUnit XML: every current finding is a
  `<testcase>` and each gate-triggering finding a `<failure>`, with all content
  XML-escaped. Together with the SARIF report (reused from `reporting/`) this feeds CI
  dashboards and the GitHub Security tab.

`.github/workflows/security-scan.yml` is an example workflow: it runs an authorized
scan, uploads the SARIF to code scanning, and fails the job on a new High/Critical
finding while still publishing the JSON / SARIF / JUnit artifacts.

## Supply-chain (SBOM) analysis

`sbom/` extends detection to the software supply chain without touching a target:
it reads a **CycloneDX** component inventory (the JSON emitted by `syft`,
`cdxgen`, `pip-audit`, and most build tooling) and asks the **OSV.dev** advisory
database which known vulnerabilities affect each declared component.

- `cyclonedx.py` parses the document into a typed `Sbom` (a *subject* -- the
  application described -- plus `Component`s with name/version/purl). Parsing is
  pure and lenient in the usual honest way: malformed entries are skipped,
  duplicates keep their first occurrence, and a non-CycloneDX `bomFormat` is
  rejected outright.
- `osv_client.py` mirrors the enrichment clients: one JSON POST per
  `purl@version` (cached on disk for a day), pure response parsing, retries with
  backoff, and failure degrading to an empty result with a logged warning. Among
  an advisory's CVSS vectors the highest-scoring parseable one wins.
- `analyzer.py` normalizes each advisory into a standard `Finding` through the
  same `make_finding` path the scanners use: `host` is the SBOM subject (a stable
  identity, so baselines survive application releases), `plugin_id` is the OSV id,
  severity derives from the advisory's own CVSS vector (or stays informational
  when there is none -- unknown, never guessed), and the remediation line is
  stated only when OSV declares fixed versions. Components without a purl or
  version are skipped with a warning: reported as unanalyzed, not silently clean.
- `pipeline.py` composes the stages for the `sbom` CLI command: load -> OSV ->
  EPSS + KEV enrichment (both keyless) -> dedup -> prioritize. The output is
  ordinary findings JSON, so `report`, `stats`, `diff`, `baseline`, `trend`, and
  `gate` all work on supply-chain results unchanged.

Because this layer only reads a local file and queries public advisory data, it
sits outside the authorization-scope gate that governs active scanning.

## Importing third-party scanner output

`ingest/` extends the "one model for everything" thesis to scanners vulnpipe does
not drive itself. Given a JSON report from **Trivy** (`trivy.py`) or **Grype**
(`grype.py`) — the two dominant open-source container / SBOM scanners — a pure
`dict → list[Finding]` parser maps the scanner's severity, its highest-scoring CVSS
entry, the CVE/CWE identifiers, and the declared fix version onto a standard finding,
carrying package identity (name / version / purl) in metadata so imports flow into
the remediation planner and everything else unchanged. Parsers are lazily dispatched
by name through a small registry (no import cycle), and a document that is not the
expected shape raises `IngestError` rather than emitting partial garbage.

The `convert` CLI command wires it up: it reads a report, normalizes it, dedups and
re-prioritizes, and emits ordinary findings JSON (or any report format). Like the
SBOM layer it is passive — a local file, nothing probed — so it needs no scope or
`--authorized`, and its output composes with `merge` (fold an imported container scan
into a network/web scan under one baseline and gate), `remediate`, `sla`, and the rest.

The same importers are also available *inside* a scan: a config can list reports under
`imports:` (each a `path` + `format`), and the orchestrator ingests them as an extra
passive layer (`_default_imports_scan`) alongside the SBOM layer — so a single `scan`
covers native scanners plus imported results under one enrich → dedup → prioritize →
diff → gate path, without a separate `convert` + `merge` step.

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
active scans are resource-heavy. When `nuclei.enabled` is set, an optional Nuclei
layer scans that same in-scope URL set with template-based CVE / misconfiguration
checks, complementing ZAP; it is off by default so existing runs are unchanged. The
combined findings then flow through enrich → dedup → false-positive filter →
prioritize → diff → gate. Scanners are resolved by name through the registry and
never special-cased; the per-layer scan callables are injectable so the pipeline is
testable without real tools.

The CLI (`cli/main.py`, Typer) exposes four commands:

- `scan` — the authorization gate: it requires `--authorized` plus an in-scope scope
  file, runs the pipeline, writes the canonical JSON report (and optional SARIF / HTML
  / JUnit), and exits non-zero when the gate trips on a newly introduced severe
  finding. Reports are written *before* the gate exit, so CI can still upload them.
- `validate` — dry-run a config through `core/planner.build_scan_plan` (pure): print
  the in-scope network/web targets, enrichment sources, and required secret env vars,
  and exit non-zero if any target is out of scope or the scope allowlist is empty.
- `sbom` — analyze a CycloneDX SBOM against OSV.dev and emit standard findings
  (any report format on stdout, plus an optional `sbom.json`); passive, so it
  needs no scope or `--authorized`.
- `convert` — import a third-party scanner report (Trivy / Grype JSON) into
  normalized findings via the `ingest/` parsers, so the whole toolchain applies to
  it; passive, no scope or `--authorized`.
- `gate` — re-evaluate the CI gate over an existing findings JSON without
  rescanning, using a policy file or the severity/risk options (text or JSON
  verdict, non-zero exit on violation).
- `sla` — report findings open past their per-severity remediation deadline, by age
  from an age-tracked baseline (`first_seen`) evaluated as of `--as-of` (text or JSON,
  non-zero exit on a breach).
- `report` — render a findings JSON to any report format on stdout.
- `serve` — serve a findings JSON as a local read-only dashboard + JSON API
  (`/`, `/api/*`, `/metrics`, `/healthz`); passive, so it needs no scope or
  `--authorized`.
- `remediate` — group a findings JSON into a ranked, deduplicated remediation plan
  (text / JSON / Markdown), most impactful fix first; `--top` limits the list.
- `merge` — combine findings JSONs from separate runs (network scan + SBOM
  analysis, or per-segment scans) into one deduplicated, re-prioritized report,
  so a single baseline and gate can cover everything.
- `stats` — print a terminal summary of a findings JSON (severity breakdown, top
  risks, worst-affected hosts) via a fixed-width Rich render.
- `badge` — render a findings JSON into a shields-style SVG status badge.
- `diff` — classify a findings JSON against a baseline (text, JSON, Markdown for a
  PR comment, or a self-contained HTML page).
- `trend` — analyze a chronological series of findings JSONs: per-scan totals and
  severity mix, findings introduced/resolved between scans (matched by fingerprint),
  and whether the critical+high backlog is trending up or down (`ci/trends.py`, pure);
  renders as text, JSON, or a self-contained HTML page with an inline SVG chart.
- `notify` — post a findings summary to a Slack-compatible webhook (`notify/`); the
  webhook URL is a secret resolved from the environment and never logged.
- `baseline` — create or update a baseline from a findings JSON.

## Docker packaging

`docker/` ships a one-command lab run: `docker compose up --build` brings up an
OWASP ZAP daemon and the scanner on a shared network and runs an authorized scan
end-to-end.

- **Image** (`docker/Dockerfile`) is multi-stage: a builder installs vulnpipe and
  its dependencies into an isolated virtualenv, and a slim runtime stage copies just
  that venv and adds the `nmap` binary (plus `curl` for the readiness wait). It runs
  as an unprivileged `scanner` user; without `NET_RAW`, nmap uses TCP connect scans.
- **Compose** (`docker/docker-compose.yml`) defines two services — `zap`
  (`ghcr.io/zaproxy/zaproxy:stable`, run as a daemon with its API reachable from the
  network) and `scanner` — on a shared `vulnpipe` bridge network. The scanner reaches
  ZAP at `http://zap:8080`; the example config resolves that from `${ZAP_API_URL}`,
  which compose sets. Reports land in the `vulnpipe-results` volume.
- **Entrypoint** (`docker/entrypoint.sh`) polls the ZAP API until it answers before a
  `scan` runs (other subcommands skip the wait), so the scan never starts against a
  daemon that is not ready yet.

Required environment (via the shell or a gitignored `.env`; see `.env.example`):
`ZAP_API_KEY` (must match the daemon), `ZAP_API_URL` (optional; defaults to
`localhost`, compose sets `http://zap:8080`), `NVD_API_KEY` (optional, raises NVD
rate limits), and any auth credentials referenced by the targets file
(`APP_USERNAME` / `APP_PASSWORD`, `API_BEARER_TOKEN`). Secrets are referenced by
name and never committed.

## Extension points

- **New scanner:** subclass `BaseScanner`, implement `scan() -> list[Finding]`,
  and register it via `scanners/registry.py`. Do not special-case scanners in the
  orchestrator.
- **New reporter:** subclass `BaseReporter`, implement `render()`, and register it in
  `reporting/__init__.py` (`register_reporter`) so `get_reporter` can resolve it.
- **Third-party plugins (no fork required):** an installed package can advertise
  scanners and reporters under the `vulnpipe.scanners` / `vulnpipe.reporters`
  entry-point groups; `vulnpipe.plugins.load_plugins()` discovers and registers
  them at CLI startup, and `vulnpipe plugins` lists what was loaded. Discovery is
  defensive and deterministic: entry points are processed in sorted order, a
  broken plugin degrades to a logged warning (it can never take down the
  pipeline), and a plugin may not shadow an already-registered name — built-ins
  register first and always win, with the collision warned about.

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

Each asset rule may also declare an optional **`owner`** (the team/queue that owns
the asset) and free-form **`tags`**, resolved the same first-match way
(`owner_for` / `tags_for`). After prioritization the orchestrator applies
`processing/ownership.annotate_ownership`, which stamps the resolved owner/tags onto
each finding's `metadata`. Ownership is operator-supplied *triage context, not
detection data*: it lives in metadata (which the fingerprint ignores), so it never
changes a finding's identity or its baseline/diff classification, and it is echoed
from config, never fabricated. It then surfaces as an "by owner" view in the `stats`,
Markdown, and HTML reports and as `owner` / `tags` columns in the CSV — so a report is
actionable per team. Like the prioritizer, `annotate_ownership` takes resolver
callables rather than a config object, keeping `processing/` pure and decoupled.
