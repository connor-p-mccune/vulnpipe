# Architecture decision records

Short records of the design decisions that shaped vulnpipe and the trade-offs
behind them. They complement [`ARCHITECTURE.md`](ARCHITECTURE.md) (which describes
*what* the system is) by capturing *why* it is that way.

Format per record: **Context → Decision → Consequences** (including trade-offs).

---

## ADR-0001 — One normalized `Finding` model for every scanner

**Context.** Nmap and ZAP describe issues completely differently (XML service/NSE
output vs. a JSON alert with risk/confidence/CWE). Downstream stages — enrichment,
dedup, filtering, prioritization, reporting, CI diffing — would otherwise each need
to understand both shapes.

**Decision.** Every scanner normalizes to a single `core.models.Finding`
(`processing/normalizer.make_finding`). Nothing downstream knows which tool produced
a finding except via `Finding.source`.

**Consequences.** Each new stage is written once against one model; adding a scanner
doesn't ripple through the pipeline. The cost is an up-front mapping layer per
scanner and a model that must be a superset of what any scanner expresses.

## ADR-0002 — A stable, content-derived fingerprint

**Context.** Deduplication and cross-run CI diffing both need to decide whether two
findings are "the same issue" — within a run and across runs months apart.

**Decision.** Each finding carries
`sha256(host | port | source | plugin_or_alert_id | normalized_title)` as a computed
field. The title is whitespace- and case-normalized so cosmetic scanner wording
changes don't change identity.

**Consequences.** Dedup is a group-by, and the differ is a set comparison by
fingerprint — both trivial and deterministic. The trade-off: the fingerprint inputs
are fixed, so a finding that legitimately changes host/port/title is treated as a
new issue (correct for diffing, but it means titles must stay stable).

## ADR-0003 — Immutable findings; stages copy rather than mutate

**Context.** Several stages add data (enrichment fills CVSS/EPSS; dedup merges
detail). Shared mutable objects across a thread pool invite subtle bugs.

**Decision.** `Finding` is `frozen`; stages produce new findings via `model_copy`.
None of the enriched/merged fields feed the fingerprint, so identity survives.

**Consequences.** Thread-safe by construction and easy to reason about; a finding's
identity is invariant from creation to report. The cost is allocation churn (a new
object per transform), which is negligible at this scale.

## ADR-0004 — Pure `processing/`, side effects at the edges

**Context.** Dedup, false-positive filtering, and prioritization are the most
logic-dense parts and the most important to test exhaustively.

**Decision.** `processing/` is pure functions (findings in → findings out). All side
effects — running tools, HTTP, file writes — live in `scanners/`, `enrichment/`, and
`reporting/`. Prioritization even takes its asset-criticality resolver as an
argument so it never imports config loading.

**Consequences.** The hardest logic is tested with plain values and no mocks, and is
reused by the CLI and orchestrator alike. The trade-off is a little plumbing to pass
dependencies in rather than reaching for them.

## ADR-0005 — Authorization and scope are enforced hard rules, in depth

**Context.** An active scanner pointed at the wrong target is a legal and ethical
problem, not a bug to fix later.

**Decision.** A scan runs only with an explicit `--authorized` acknowledgement *and*
a non-empty scope allowlist; any out-of-scope target is a hard error. The check is
enforced at multiple layers — the CLI gate, the orchestrator, target selection in
each scanner, and again when normalizing results — so no single missed call opens a
hole.

**Consequences.** Redundant checks (defense in depth) over a single choke point. The
small duplication is deliberate: safety rules should fail closed even if one path is
refactored incorrectly.

## ADR-0006 — Detection only; never fabricate

**Context.** The tool wraps real scanners and enriches with external data sources
that can be slow, rate-limited, or unavailable.

**Decision.** Two firm boundaries: (1) it reports issues for remediation and never
embeds or emits exploit payloads — the ZAP integration deliberately drops the raw
`attack` vector while keeping evidence; (2) it never invents data — a failed NVD/EPSS
lookup or an unparseable CVSS leaves the field `None` (unknown), never a guess.

**Consequences.** Output is trustworthy and the project stays unambiguously
defensive. The trade-off is visible "unknown" fields when enrichment is degraded —
which is the honest result.

## ADR-0007 — Nmap once over the range; bounded fan-out for the web layer

**Context.** The target is 200+ hosts per run, but ZAP active scans are heavy and
each ZAP instance is a shared, stateful daemon.

**Decision.** Nmap handles CIDR ranges natively, so the network layer runs it once
rather than fanning out per host. The web layer is fanned out across a bounded
`ThreadPoolExecutor` (`run.max_workers`), with ZAP active-scan concurrency capped
*separately* by a `Semaphore` (`zap.max_concurrency`).

**Consequences.** Network discovery scales for free while web scanning stays within
ZAP's capacity, tuned independently of overall parallelism. The cost is two
concurrency knobs instead of one — intentional, because the two layers have very
different cost profiles.

## ADR-0008 — Deterministic outputs

**Context.** Reports and CI diffs must be reviewable and snapshot-testable;
nondeterminism (ordering, timestamps) makes regressions invisible in diffs.

**Decision.** Reporters emit findings in the prioritized order with fixed enum
ordering and **no embedded wall-clock timestamp**; baselines and diffs are ordered
by fingerprint. Identical input always produces byte-identical output.

**Consequences.** JSON/SARIF shapes and differ output are snapshot-tested, and the
canonical JSON round-trips (`build_report` → JSON → findings). The trade-off is that
"when was this scanned" lives in the surrounding CI metadata, not the report body.

## ADR-0009 — Registries for scanners and reporters

**Context.** New scanners and output formats should be addable without editing the
orchestrator or the CLI.

**Decision.** Scanners self-register via `scanners/registry.py` and are resolved by
name; reporters register in `reporting/__init__.py` and resolve through
`get_reporter`. The orchestrator never special-cases a scanner.

**Consequences.** Extension is "subclass + register"; the wiring is closed to
modification. The minor cost is a layer of indirection (name → class) instead of
direct imports.

## ADR-0010 — Secrets by environment-variable name only

**Context.** Scans need credentials (ZAP/NVD keys, app logins), but this is a
portfolio repo that must never leak a secret.

**Decision.** Config references secrets by environment-variable *name*; the value is
resolved at scan time via `resolve_secret` and never stored in the YAML or the
in-memory config model. `.env` is gitignored; `.env.example` documents the names.

**Consequences.** A committed config is always safe to share, and a missing
credential is a clear, early error. The trade-off is one level of indirection when
reading configs ("which env var backs this?").

## ADR-0011 — Known-exploited (KEV) as a first-class signal

**Context.** Severity and CVSS describe how bad an issue *could* be in theory. They
say nothing about whether it is *actually being exploited*, which is the single most
useful input to "what do I fix first." CISA's Known Exploited Vulnerabilities catalog
answers exactly that, for free.

**Decision.** Cross-reference every cited CVE against the KEV catalog during
enrichment and carry the result as a first-class `Finding.kev` boolean (catalog
context in metadata), rather than burying it in metadata alone. KEV then feeds
prioritization (a tie-breaker within a severity band), the risk score (full
exploitation likelihood), and the reports. A CVE absent from the catalog stays
`kev=False` — absence of evidence, never a guess — and a fetch failure degrades to an
empty catalog.

**Consequences.** "Actively exploited" is queryable and drives ordering and gating,
not just display, so an exploited Medium can out-prioritize a theoretical High. The
cost is one more enrichment source and a model field; both are cheap because the
catalog is a single cached document and the field defaults false.

## ADR-0012 — A transparent, intrinsic composite risk score

**Context.** A reviewer staring at severity, CVSS, EPSS, and a KEV flag has to combine
four numbers in their head to rank findings. A single score helps — but an opaque or
fabricated one would violate the project's "never invent data" rule and be impossible
to trust.

**Decision.** Compute a `risk_score` (0–100) as a documented function of fields the
finding already carries: technical impact (CVSS, or a per-severity fallback) modulated
by exploitation likelihood (KEV → full, else EPSS, else a conservative zero floor).
It is *intrinsic* to the finding — asset criticality stays a separate,
context-dependent concern in the prioritizer — so it can be a pure computed field that
flows into every report for free and is stripped on JSON round-trip like the
fingerprint. It is a ranking aid, not a data source: it fabricates nothing.

**Consequences.** Reports and the CI gate get one honest urgency number
(`--gate-risk-score`), and because the formula is a small documented function it is
easy to test and to explain. The trade-off is that any weighting is a judgement call;
keeping it transparent and intrinsic (not folding in external context) makes the
judgement inspectable rather than hidden.

## ADR-0013 — Standards mapping as curated reference data, outside the model

**Context.** Findings carry CWE references, but a bare `CWE-79` means little to the
people reports are written for. The frameworks they actually speak — the OWASP Top
10 and the CWE Top 25 — are published mappings that change on their own cadence,
not per-scan data.

**Decision.** Hold a curated copy of the official OWASP Top 10 2021 CWE mapping and
the 2023 CWE Top 25 as pure reference data (`core/standards.py`) with pure lookups,
and apply it **at render time** through a shared view-model. It never enters the
`Finding` model or the canonical JSON; a CWE outside the curated map yields no
category (the finding reports as *unmapped*).

**Consequences.** Every format gains OWASP/Top-25 context from one source that
cannot drift per-reporter, JSON round-tripping and fingerprints are untouched, and
updating to a future Top 10 revision is a data edit, not a migration. The trade-off
is a curated snapshot that must be refreshed when the standards are — acceptable
because the standards change every few years and the file documents its sources.

## ADR-0014 — Policy-as-code gating over a single threshold

**Context.** One severity threshold cannot express real gating policies: "no new
criticals, at most five new mediums, and never a new known-exploited finding" is
three different rules. Teams also need the gate decision reviewable in a PR, not
embedded in CI flags.

**Decision.** A declarative `GatePolicy` YAML (severity budgets, a total cap, a
risk-score threshold, a KEV block) evaluated purely over the baseline diff
(`ci/policy.py`). The plain threshold gate remains, and `policy_from_threshold`
expresses it *as* a policy so both forms share one evaluation path; JUnit and the
CLI consume either verdict through a structural `GateVerdict` protocol rather than
a shared base class.

**Consequences.** Gate rules live in a reviewed file with deterministic, per-rule
violation reporting, and the standalone `gate` command re-evaluates a findings JSON
without rescanning. The trade-off is two verdict types in flight; the protocol
keeps them interchangeable where it matters and avoids retrofitting the existing
`GateResult` API.

## ADR-0015 — Supply-chain analysis via OSV, keyed to the SBOM subject

**Context.** A deployment's risk includes what it is *built from*, not just what
it exposes on the network. SBOMs (CycloneDX) declare that inventory, and OSV.dev
answers "which advisories affect this package version" across ecosystems, for
free and without credentials. Analyzing an SBOM is passive — no target is probed —
so forcing it through the scan authorization gate would be wrong.

**Decision.** A separate `sbom/` layer and CLI command outside the orchestrator:
parse CycloneDX, query OSV per component (cached, worst CVSS vector wins),
normalize each advisory through the same `make_finding` path as the scanners with
`source="sbom"`. `Finding.host` is the SBOM **subject** (the application name, not
its version), so fingerprints — and therefore baselines and diffs — survive
application releases. Advisories without a CVSS vector stay informational; skipped
(unqueryable) components are logged, never silently treated as clean.

**Consequences.** Supply-chain findings flow through the existing reporting,
enrichment (EPSS/KEV), diffing, and gating machinery unchanged, and the command
needs no scope file. The trade-offs are deliberate: subject-level identity means
two SBOMs analyzed under the same subject share a namespace, and severity for
unscored advisories understates risk until enrichment/risk scoring lifts it —
both preferred over inventing identity or severity.

## ADR-0016 — OpenVEX output: only `affected`, only real identifiers

**Context.** VEX (Vulnerability Exploitability eXchange) is how tooling ingests
"is this product affected by this vulnerability" machine-readably; OpenVEX is its
lightweight open spec, consumed by `vexctl`, scanners, and policy engines. Two
tensions: a VEX statement asserts an exploitability *judgement* vulnpipe does not
make, and the spec requires a publication `timestamp` while every vulnpipe
reporter is deterministic by convention.

**Decision.** Emit statements only for findings that cite a real vulnerability
identifier (a CVE, else the SBOM layer's OSV id — hygiene alerts emit nothing),
and assert only the `affected` status: every finding *is* a detection, whereas
`not_affected` / `fixed` would fabricate an assessment. KEV listings ride along as
`status_notes`. The document `@id` is content-addressed from the statements. For
the timestamp, split by purity: `build_vex` / `render_vex` omit it unless one is
passed, while the registered reporter (the CLI publication path) stamps real UTC
time and honors `SOURCE_DATE_EPOCH`, the reproducible-builds convention.

**Consequences.** A scan or SBOM run can feed the VEX ecosystem directly
(`sbom -f vex` closes the supply-chain loop), and downstream triage decisions
(`not_affected` with a justification) stay where they belong — with a human,
e.g. via `vexctl` merging vulnpipe's document with a curated one. Library output
remains snapshot-testable and CI output byte-reproducible under a pinned epoch;
the cost is that CLI VEX output varies run-to-run by default, which is exactly
what a publication timestamp is supposed to do.

## ADR-0017 — Suppressions are time-boxed risk acceptances

**Context.** A false-positive allowlist quietly accumulates: entries added for a
good reason outlive the reason, and nothing ever forces a review. In practice a
suppression is a *risk acceptance*, and risk acceptances have owners, rationale,
and review dates.

**Decision.** Every allowlist entry (fingerprint, plugin, host) accepts an
optional `reason` and an optional, **inclusive** `expires` date ("accepted until
2026-09-30" suppresses through that day). Expiry is evaluated against an
injectable `today` so the filter stays a pure, pinnable function; the
orchestrator resolves the real date once per run. A lapsed entry does not error
and is not deleted — it simply stops suppressing, the finding resurfaces in
reports and the gate, and the run logs a warning naming the entry. Bare-string
entries remain valid (indefinite acceptance) for backward compatibility. The
`min_confidence` floor never expires: it is a quality bar, not an acceptance.

**Consequences.** Expired acceptances self-enforce their review: the finding
comes back and the gate can fail, which is the correct pressure. The audit
trail (why was this accepted?) lives in the allowlist file under version
control. The trade-off is that filter output now depends on the run date when
expiring entries are present — deliberate, bounded to entries that opt in, and
tests pin the date explicitly.

## ADR-0018 — Plugin discovery through entry points, built-ins win

**Context.** The scanner and reporter registries already decouple integrations
from the orchestrator, but adding one still means editing this repository.
Python's packaging metadata (entry points) is the standard way for installed
packages to advertise extensions — it is how pytest, Flake8, and friends load
plugins.

**Decision.** `vulnpipe.plugins.load_plugins()` scans the `vulnpipe.scanners`
and `vulnpipe.reporters` entry-point groups at CLI startup and registers valid
classes (concrete `BaseScanner` / `BaseReporter` subclasses with a non-empty
`name`). Three rules shape it: entry points are processed in sorted order
(deterministic registration); any plugin failure — import error, wrong type,
missing name — degrades to a logged warning, never an exception; and a plugin
cannot shadow an already-registered name — built-ins are imported first and
always win, with the collision warned about rather than silently resolved.
Loading is idempotent, so repeated calls are safe.

**Consequences.** A third party can ship `vulnpipe-nikto` or `vulnpipe-xlsx`
without forking, and the orchestrator/CLI stay unchanged (they already resolve
by name). Refusing overrides means a plugin cannot quietly replace the `nmap`
integration or the canonical `json` format — a deliberate supply-chain guard;
anyone who truly wants to swap a built-in must do it in code, visibly. The cost
is a process-global registry mutated at startup, mitigated by determinism and
the idempotence guarantee.

## ADR-0019 — Remediation planning as a re-view of the report, not new data

**Context.** A prioritized findings list still leaves an operator asking "so what
do I *do*, and in what order?" Several findings usually share one fix — three CVEs
on one Apache build, a dozen advisories on one dependency — so a flat list overstates
the work and hides the highest-leverage actions.

**Decision.** `reporting/remediation.plan_remediations` (pure) groups findings by the
action that resolves them — a dependency by **package**, a network service by
**product-per-host**, everything else by **weakness class** — and ranks the groups by
known-exploited status, then severity, then the total composite risk each removes,
then count. An action's instruction reuses the scanner's own `solution` text when it
exists and otherwise uses a template that never names a fixed version. The one planner
backs the `remediate` command, the HTML panel, and the `stats` table.

**Consequences.** The plan is genuinely actionable ("patch this, upgrade that") and
invents nothing — every number traces to a finding it contains, and a missing fix is
stated as such rather than fabricated. Grouping keys are heuristics over metadata
(`package` / `product`), so a scanner that omits that metadata falls back to the
per-title class grouping; that is a graceful degradation, not a wrong answer. Because
it is a pure view over existing findings, it needs no new model field and cannot drift
from the report.

## ADR-0020 — Nuclei as an opt-in third scanner, detection-only

**Context.** Nmap (network) and ZAP (web) leave gaps that ProjectDiscovery's Nuclei —
a fast, community-templated scanner — fills well: known-CVE checks, misconfigurations,
and exposures. But Nuclei can also run fuzzing / exploitation templates, which would
violate the project's detection-only rule, and adding a third scanner by default would
change every existing run.

**Decision.** Add `NucleiScanner` through the same registry + injectable-seam path as
the other scanners, wired as an optional orchestrator layer over the same in-scope web
URLs as ZAP. It is **off unless `nuclei.enabled`**, and the integration runs only
detection templates: it passes no fuzzing/exploitation flags and carries the match
location and evidence onto a finding but never a replayable payload. Severity, CVE/CWE,
and CVSS come verbatim from the template classification.

**Consequences.** vulnpipe gains modern template-based coverage without special-casing
anything in the orchestrator, and existing runs are byte-for-byte unchanged because the
layer defaults off. Keeping it detection-only preserves the hard rule at the cost of not
surfacing Nuclei's exploitation templates — the right trade for a detect-and-report tool.
Overlap with ZAP on the same URLs is deliberate: the two find different classes of issue,
and dedup collapses any genuine duplicates by fingerprint.

## ADR-0021 — Export to the CI platform's native format (SARIF and GitLab)

**Context.** SARIF already lands findings in the GitHub Security tab. GitLab — the other
dominant CI platform — does not read SARIF for its Vulnerability Report; it ingests its
own security-report JSON. Meeting teams where they already triage matters more than
adding a novel format.

**Decision.** Add a `gitlab` reporter emitting a GitLab-compatible security report.
vulnpipe is a dynamic scanner, so it exports a DAST-style report: the vulnerability `id`
is the stable fingerprint (GitLab tracks the same issue across pipelines), `identifiers`
carry the real CVEs/CWEs plus a vulnpipe rule id so the list is never empty, and severity
maps onto GitLab's vocabulary. The schema-required `scan.start_time` / `end_time` are
handled exactly like the OpenVEX timestamp: the pure builder omits them (snapshot-stable)
while the registered reporter stamps them, honoring `SOURCE_DATE_EPOCH`.

**Consequences.** A single scan now surfaces natively in either GitHub or GitLab with no
extra tooling. The cost is a second machine format to keep honest, but it reuses the same
finding fields and the same reproducible-timestamp discipline as SARIF and OpenVEX, so the
marginal maintenance is small. The report is framed as one scan type (DAST) rather than
splitting network/web/SBOM findings across GitLab's report types — a pragmatic choice that
keeps every finding in one ingestible document.

## ADR-0022 — Finding age lives in the baseline, and SLAs use an injected clock

**Context.** The gate governs *new* risk; a mature program also governs *dwell time* —
how long an accepted finding may stay open. That needs to know when each finding was first
seen. Two temptations to avoid: putting a date on the `Finding` model (which would break its
content-derived fingerprint and its determinism), and reading the wall clock inside the
evaluation (which would make results non-reproducible).

**Decision.** Record `first_seen` as an optional field on the *baseline entry*, not the
finding — the baseline is already the stateful, per-run artifact, and the finding stays a
pure, immutable value. Stamp it only when asked (`baseline --track-age`), preserve it across
merges so age counts from the true first appearance, and omit it from the on-disk form when
unset so age-untracked baselines are byte-identical to pre-feature ones. `evaluate_sla` is
pure over (findings, baseline, policy, `today`), with `today` injected — the CLI defaults it
to the real date but `--as-of` pins it. A finding with no recorded date is *untracked* and
never breaches.

**Consequences.** The `Finding` model and its fingerprint are untouched, so nothing
downstream changes; SLA reporting is a clean overlay on the existing baseline/differ
machinery. Determinism holds: the same inputs and `--as-of` always yield the same verdict,
so SLA tests pin a date and CI is reproducible. The trade-off is that age tracking is only
as good as the baseline discipline — a team that never stamps first-seen dates gets an
all-untracked (and therefore always-passing) SLA report, which is the honest answer when the
age is genuinely unknown rather than a fabricated one.

## ADR-0023 — Ingest other scanners' output, don't reinvent their engines

**Context.** vulnpipe drives Nmap, ZAP, and Nuclei, but a lot of real risk data already
exists in reports teams generate elsewhere — most commonly Trivy and Grype for container and
SBOM scanning. Re-implementing those engines would be wasteful and dishonest (they are
mature, specialized tools); ignoring their output would waste vulnpipe's real value, which is
everything that happens *after* detection: normalization, prioritization, remediation
planning, gating, SLAs, and reporting.

**Decision.** Add an `ingest/` layer of pure `dict → list[Finding]` parsers (Trivy, Grype)
and a `convert` command. Each parser maps the source report's own severity, CVSS, identifiers,
and fix version onto the shared model — inventing nothing, leaving a missing field `None` — and
carries package identity in metadata so imports feed the remediation planner like native
findings. Parsers are passive (read a file, map it) and lazily dispatched through a registry;
a wrong-shaped document raises `IngestError`.

**Consequences.** vulnpipe becomes a normalization and decisioning hub, not just a scanner
wrapper: a Trivy container scan and a native network/web scan can `merge` into one baseline,
gate, and remediation plan. The cost is per-scanner mapping code and coupling to each report's
JSON shape (which can change across versions), bounded by keeping the parsers small, pure, and
fixture-tested. The alternative — one universal "SARIF-in" importer — was rejected because
neither Trivy nor Grype's native, richest output is SARIF, and meeting them in their own format
loses less information.

## ADR-0024 — Serve reports over the standard library, read-only, no framework

**Context.** A findings JSON is useful rendered to a file, but a report people can *browse and
query* — an HTML dashboard, a JSON API for automation, a `/metrics` endpoint for scraping — is
materially more useful, and it is a natural way to demonstrate the pipeline. The obvious risk is
scope creep: a web service invites statefulness, a database, authentication, write endpoints,
and a heavyweight framework dependency, none of which belong in a detection-and-reporting tool.

**Decision.** Add `vulnpipe serve` as a strictly **read-only** HTTP view over an
already-computed report, built on the standard-library `http.server` alone — no Flask/FastAPI
dependency. Split it into a pure `path → Response` router (`server/routes.py`) that delegates to
the existing reporters, and a thin socket adapter (`server/http_server.py`) that owns only
sockets and lifecycle. The server never scans, never mutates state, and reads no request body;
mutating verbs return `405`, it binds loopback by default (a non-loopback bind is warned about),
and responses carry `nosniff` / `no-store`. Because it is passive it lives outside the
authorization gate, exactly like `report` and `stats`.

**Consequences.** The whole surface is a new *transport* for the same deterministic data, not a
second code path — every route renders through a reporter, so the API cannot drift from the file
output, and the pure router is exhaustively unit-testable without a socket (the adapter is
covered by a single loopback round-trip). Keeping it framework-free means no new dependency and
no attack surface beyond a GET router, at the cost of not being a multi-tenant application
server — which is the point. If persistent hosting, auth, or write operations are ever needed,
that is a different tool; `serve` deliberately stops at "browse and query a report locally."
