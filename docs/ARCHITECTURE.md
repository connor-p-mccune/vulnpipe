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

## Extension points

- **New scanner:** subclass `BaseScanner`, implement `scan() -> list[Finding]`,
  and register it via `scanners/registry.py`. Do not special-case scanners in the
  orchestrator.
- **New reporter:** subclass `BaseReporter` and implement `render()`.

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
