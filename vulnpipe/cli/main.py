"""``vulnpipe`` command-line interface (Typer).

Wires configuration loading and the authorization/scope guards to the pipeline
orchestrator and the CI stage. Commands:

* ``scan`` -- run the full pipeline (refusing to start without ``--authorized`` and
  a scope file), write the JSON report (and optional SARIF / HTML / JUnit), and
  exit non-zero when the gate trips on a newly introduced severe finding;
* ``report`` -- render a findings JSON into JSON / HTML / SARIF on stdout;
* ``diff`` -- classify a findings JSON against a baseline (new / persisting /
  resolved);
* ``baseline`` -- create or update a baseline from a findings JSON.

The ``scan`` command is the authorization gate: it enforces the hard rules before
any scanner runs.
"""

import json
import logging
from pathlib import Path
from typing import Annotated

import click
import typer
from pydantic import ValidationError

from vulnpipe import __version__
from vulnpipe.ci.baseline import (
    Baseline,
    BaselineError,
    build_baseline,
    load_baseline,
    merge_baseline,
    save_baseline,
)
from vulnpipe.ci.differ import Diff, diff_findings, diff_to_payload
from vulnpipe.ci.gate import DEFAULT_GATE_SEVERITY
from vulnpipe.ci.junit import build_junit_xml
from vulnpipe.core.config import (
    ConfigError,
    ensure_authorized,
    ensure_config_in_scope,
    load_config,
)
from vulnpipe.core.logging import configure_logging, get_logger
from vulnpipe.core.models import Severity
from vulnpipe.core.orchestrator import PipelineResult, run_pipeline
from vulnpipe.processing import FalsePositiveConfig, load_false_positive_config
from vulnpipe.reporting import (
    SEVERITY_DISPLAY_ORDER,
    available_formats,
    get_reporter,
    load_findings,
    severity_counts,
)

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Modular network + web vulnerability scanning pipeline (detection & reporting only).",
)
log = get_logger(__name__)


@app.callback()
def _root(
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable debug-level logging.")
    ] = False,
) -> None:
    configure_logging(logging.DEBUG if verbose else logging.INFO)


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
def _write(path: Path, content: str) -> None:
    """Write ``content`` to ``path``, creating parent directories as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _emit(text: str) -> None:
    """Write report text to stdout as UTF-8 bytes, regardless of console locale.

    Reports may contain non-ASCII characters (e.g. the Markdown format's severity
    markers). Emitting through the binary stream keeps ``vulnpipe report ... > file``
    deterministic on any platform rather than failing on a legacy console encoding.
    """
    click.get_binary_stream("stdout").write(text.encode("utf-8"))


def _load_allowlist(path: Path | None) -> FalsePositiveConfig:
    return load_false_positive_config(path) if path is not None else FalsePositiveConfig()


def _load_baseline_or_findings(path: Path) -> Baseline:
    """Load ``path`` as a baseline file, falling back to a findings JSON export."""
    try:
        return load_baseline(path)
    except BaselineError:
        return build_baseline(load_findings(path))


def _write_reports(
    result: PipelineResult,
    *,
    output: Path,
    sarif: Path | None,
    html: Path | None,
    markdown: Path | None,
    junit: Path | None,
) -> None:
    """Write the canonical JSON report plus any requested SARIF / HTML / Markdown / JUnit."""
    findings = list(result.findings)
    json_path = output / "latest.json"
    _write(json_path, get_reporter("json").render(findings))
    log.info("wrote findings JSON: %s", json_path)
    if sarif is not None:
        _write(sarif, get_reporter("sarif").render(findings))
        log.info("wrote SARIF report: %s", sarif)
    if html is not None:
        _write(html, get_reporter("html").render(findings))
        log.info("wrote HTML report: %s", html)
    if markdown is not None:
        _write(markdown, get_reporter("markdown").render(findings))
        log.info("wrote Markdown report: %s", markdown)
    if junit is not None:
        _write(junit, build_junit_xml(result.diff, result.gate))
        log.info("wrote JUnit report: %s", junit)


def _log_summary(result: PipelineResult) -> None:
    counts = severity_counts(result.findings)
    breakdown = ", ".join(f"{sev.value}={counts[sev]}" for sev in SEVERITY_DISPLAY_ORDER)
    log.info("findings: %d (%s)", len(result.findings), breakdown)
    diff = result.diff
    log.info(
        "diff: new=%d persisting=%d resolved=%d",
        len(diff.new),
        len(diff.persisting),
        len(diff.resolved),
    )
    if result.gate.passed:
        log.info("%s", result.gate.summary)
    else:
        log.error("%s", result.gate.summary)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
@app.command()
def version() -> None:
    """Print the vulnpipe version."""
    log.info("vulnpipe %s", __version__)


@app.command()
def scan(
    config: Annotated[
        Path,
        typer.Option(
            "--config",
            "-c",
            exists=True,
            dir_okay=False,
            readable=True,
            help="Path to the YAML target/scope configuration.",
        ),
    ],
    authorized: Annotated[
        bool,
        typer.Option(
            "--authorized",
            help="Acknowledge you are authorized to scan every in-scope target.",
        ),
    ] = False,
    output: Annotated[
        Path,
        typer.Option("--output", "-o", file_okay=False, help="Directory for scan artifacts."),
    ] = Path("results"),
    baseline: Annotated[
        Path | None,
        typer.Option("--baseline", dir_okay=False, help="Baseline to diff and gate against."),
    ] = None,
    gate_severity: Annotated[
        Severity,
        typer.Option("--gate-severity", help="Fail on a new finding at or above this severity."),
    ] = DEFAULT_GATE_SEVERITY,
    false_positives: Annotated[
        Path | None,
        typer.Option(
            "--false-positives", dir_okay=False, help="False-positive allowlist YAML to apply."
        ),
    ] = None,
    sarif: Annotated[
        Path | None,
        typer.Option("--sarif", dir_okay=False, help="Also write a SARIF report here."),
    ] = None,
    html: Annotated[
        Path | None,
        typer.Option("--html", dir_okay=False, help="Also write an HTML report here."),
    ] = None,
    markdown: Annotated[
        Path | None,
        typer.Option("--markdown", dir_okay=False, help="Also write a Markdown report here."),
    ] = None,
    junit: Annotated[
        Path | None,
        typer.Option("--junit", dir_okay=False, help="Also write a JUnit gate report here."),
    ] = None,
    no_gate: Annotated[
        bool,
        typer.Option("--no-gate", help="Do not exit non-zero when the gate fails."),
    ] = False,
) -> None:
    """Validate authorization/scope, run the pipeline, write reports, and gate."""
    try:
        cfg = load_config(config)
        ensure_authorized(authorized=authorized, scope=cfg.scope)
        ensure_config_in_scope(cfg)
        allowlist = _load_allowlist(false_positives)
        base = load_baseline(baseline) if baseline is not None else None
    except (ConfigError, BaselineError, OSError, ValueError, ValidationError) as exc:
        log.error("%s", exc)
        raise typer.Exit(code=2) from exc

    log.info("authorization confirmed; scanning %d target(s) in scope", len(cfg.targets))
    result = run_pipeline(
        cfg,
        authorized=True,
        allowlist=allowlist,
        baseline=base,
        gate_threshold=gate_severity,
    )
    _write_reports(result, output=output, sarif=sarif, html=html, markdown=markdown, junit=junit)
    _log_summary(result)

    if not no_gate and result.gate.exit_code != 0:
        raise typer.Exit(code=result.gate.exit_code)


@app.command()
def report(
    input_path: Annotated[
        Path,
        typer.Option("--input", "-i", exists=True, dir_okay=False, help="Findings JSON to render."),
    ],
    fmt: Annotated[
        str, typer.Option("--format", "-f", help="Report format: json, html, markdown, or sarif.")
    ] = "html",
) -> None:
    """Render a findings JSON file into a JSON, HTML, Markdown, or SARIF report on stdout."""
    try:
        reporter = get_reporter(fmt)
    except KeyError as exc:
        log.error(
            "Unknown report format %r; choose one of: %s", fmt, ", ".join(available_formats())
        )
        raise typer.Exit(code=2) from exc
    try:
        findings = load_findings(input_path)
    except (OSError, ValueError) as exc:
        log.error("Failed to read findings from %s: %s", input_path, exc)
        raise typer.Exit(code=2) from exc
    _emit(reporter.render(findings))


def _print_diff_text(diff: Diff) -> None:
    """Print a compact text summary of a diff to stdout."""
    counts = diff.counts
    typer.echo(f"new:        {counts['new']}")
    typer.echo(f"persisting: {counts['persisting']}")
    typer.echo(f"resolved:   {counts['resolved']}")
    for finding in diff.new:
        typer.echo(f"  + [{finding.severity.value}] {finding.title} ({finding.host})")
    for entry in diff.resolved:
        typer.echo(f"  - [{entry.severity.value}] {entry.title} ({entry.host})")


@app.command()
def diff(
    baseline: Annotated[
        Path,
        typer.Option("--baseline", exists=True, dir_okay=False, help="Baseline or findings JSON."),
    ],
    current: Annotated[
        Path, typer.Option("--current", exists=True, dir_okay=False, help="Current findings JSON.")
    ],
    fmt: Annotated[
        str, typer.Option("--format", "-f", help="Output format: text or json.")
    ] = "text",
) -> None:
    """Diff current findings against a baseline (new / persisting / resolved)."""
    if fmt not in {"text", "json"}:
        log.error("Unknown diff format %r; choose text or json", fmt)
        raise typer.Exit(code=2)
    try:
        base = _load_baseline_or_findings(baseline)
        current_findings = load_findings(current)
    except (BaselineError, OSError, ValueError) as exc:
        log.error("Failed to load diff inputs: %s", exc)
        raise typer.Exit(code=2) from exc
    result = diff_findings(current_findings, base)
    if fmt == "json":
        typer.echo(json.dumps(diff_to_payload(result), indent=2, ensure_ascii=False))
    else:
        _print_diff_text(result)


@app.command()
def baseline(
    input_path: Annotated[
        Path,
        typer.Option("--input", "-i", exists=True, dir_okay=False, help="Findings JSON to record."),
    ],
    output: Annotated[
        Path, typer.Option("--output", "-o", dir_okay=False, help="Baseline file to write.")
    ],
    update: Annotated[
        bool,
        typer.Option("--update", help="Merge into an existing baseline instead of replacing it."),
    ] = False,
) -> None:
    """Create or update a baseline from a findings JSON file."""
    try:
        findings = load_findings(input_path)
        if update and output.is_file():
            result = merge_baseline(load_baseline(output), findings)
        else:
            result = build_baseline(findings)
    except (BaselineError, OSError, ValueError) as exc:
        log.error("Failed to build baseline: %s", exc)
        raise typer.Exit(code=2) from exc
    save_baseline(result, output)
    log.info("wrote baseline %s (%d entries)", output, len(result.entries))


def main() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":
    main()
