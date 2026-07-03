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
