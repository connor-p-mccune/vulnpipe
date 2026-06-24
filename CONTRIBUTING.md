# Contributing to vulnpipe

Thanks for your interest in improving vulnpipe. This guide covers the development
setup, the quality bar every change must clear, and the conventions that keep the
codebase consistent.

Please also read [`SECURITY.md`](SECURITY.md): vulnpipe's authorization and
detection-only guardrails are non-negotiable, and changes that weaken them will not
be accepted.

## Development setup

vulnpipe targets **Python 3.12+** and is fully type-hinted.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install
```

This installs the package in editable mode with the dev tooling (pytest, ruff,
black, mypy, respx, pre-commit) and wires up the pre-commit hooks.

## Quality gates

A change is "done" only when all four of these pass — they also run in pre-commit:

```bash
ruff check .          # lint
black --check .       # formatting
mypy vulnpipe         # type checking (strict)
pytest                # unit tests
```

`pytest --cov=vulnpipe` reports coverage; keep it at **≥ 80%**. Every scanner,
enrichment client, processor, and reporter ships with tests, and the CI gate logic
is covered end to end with a synthetic baseline-vs-current pair.

## Testing rules

- Unit tests live under `tests/unit/`; integration tests under `tests/integration/`
  and carry `@pytest.mark.integration` (skipped unless you run `pytest -m
  integration`).
- **Unit tests never touch the network or run real scanners.** Drive them from the
  fixtures in `tests/fixtures/` (a sample Nmap `-oX` XML file and a sample ZAP
  `core.alerts` JSON payload). Mock outbound HTTP (NVD, EPSS) with `respx`, and mock
  the ZAP client and the Nmap `subprocess` call.
- `processing/` functions are pure: give them findings and assert on the transformed
  findings.
- Fingerprints and report output must be **deterministic** for fixed fixture input.
  Snapshot the JSON report shape and the differ output so regressions are obvious.

## Code conventions

- Every scanner finding conforms to `vulnpipe.core.models.Finding`. It carries a
  stable fingerprint, `sha256(host | port | source | plugin_or_alert_id |
  normalized_title)`, used for dedup and baseline diffing — keep it stable across
  runs for the same underlying issue.
- Build findings through `processing/normalizer.make_finding` so field conventions
  (trimming, CVE validation, CVSS-derived severity) stay uniform.
- Each scanner subclasses `BaseScanner` and implements `scan() -> list[Finding]`.
  Register new scanners through `scanners/registry.py` — don't special-case them in
  the orchestrator.
- Keep `processing/` pure (findings in → findings out). Side effects — running
  tools, HTTP, writing files — stay in `scanners/`, `enrichment/`, and `reporting/`.
- Log through the rich-backed logger in `core/logging.py`; never use `print`.
- Subprocess calls pass an argument list — never `shell=True` with interpolated
  target input.
- Secrets resolve from the environment by variable name; never read or commit a
  credential or API key.

## Extending vulnpipe

- **New scanner:** subclass `BaseScanner`, implement `scan() -> list[Finding]`
  (normalizing through `make_finding`), and register it via `scanners/registry.py`.
- **New reporter:** subclass `BaseReporter`, implement `render()`, and register it in
  `reporting/__init__.py` so `get_reporter` can resolve it.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design.

## Commit and pull-request etiquette

- Use clear, conventional commit messages (e.g. `feat(scanners): ...`,
  `fix(ci): ...`, `docs(readme): ...`).
- Keep changes focused, and add or update tests alongside code.
- Make sure the quality gates pass locally before opening a pull request.
