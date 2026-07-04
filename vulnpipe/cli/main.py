"""``vulnpipe`` command-line interface (Typer).

Wires configuration loading and the authorization/scope guards to the pipeline
orchestrator and the CI stage. Commands:

* ``scan`` -- run the full pipeline (refusing to start without ``--authorized`` and
  a scope file), write the JSON report (and optional SARIF / HTML / JUnit), and
  exit non-zero when the gate trips on a newly introduced severe finding;
* ``gate`` -- re-evaluate the CI gate (severity threshold or a policy file) over an
  existing findings JSON without rescanning;
* ``sbom`` -- analyze a CycloneDX SBOM for known-vulnerable dependencies (OSV.dev);
* ``report`` -- render a findings JSON into JSON / HTML / SARIF on stdout;
* ``diff`` -- classify a findings JSON against a baseline (new / persisting /
  resolved);
* ``baseline`` -- create or update a baseline from a findings JSON.

The ``scan`` command is the authorization gate: it enforces the hard rules before
any scanner runs.
"""

import json
import logging
import os
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
from vulnpipe.ci.differ import (
    Diff,
    diff_findings,
    diff_to_payload,
    render_diff_html,
    render_diff_markdown,
)
from vulnpipe.ci.gate import DEFAULT_GATE_SEVERITY
from vulnpipe.ci.junit import GateVerdict, build_junit_xml
from vulnpipe.ci.policy import (
    GatePolicy,
    PolicyError,
    PolicyResult,
    evaluate_policy,
    load_policy,
    policy_from_threshold,
    policy_result_to_payload,
)
from vulnpipe.ci.trends import build_trend, render_trend_text, trend_to_payload
from vulnpipe.core.config import (
    Config,
    ConfigError,
    ensure_authorized,
    ensure_config_in_scope,
    load_config,
)
from vulnpipe.core.logging import configure_logging, get_logger
from vulnpipe.core.models import Finding, Severity
from vulnpipe.core.orchestrator import PipelineResult, run_pipeline
from vulnpipe.core.planner import build_scan_plan, render_plan
from vulnpipe.notify import NotifyError, post_webhook
from vulnpipe.plugins import REPORTER_GROUP, SCANNER_GROUP, load_plugins, loaded_plugins
from vulnpipe.processing import (
    FalsePositiveConfig,
    deduplicate,
    load_false_positive_config,
    prioritize,
)
from vulnpipe.reporting import (
    SEVERITY_DISPLAY_ORDER,
    available_formats,
    build_report_schema,
    get_reporter,
    load_findings,
    render_badge,
    render_stats,
    severity_counts,
)
from vulnpipe.sbom import SbomError, run_sbom_pipeline

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
    # Register any scanner/reporter plugins installed packages advertise, before
    # the command resolves scanners or report formats.
    load_plugins()


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
    verdict: GateVerdict,
    *,
    output: Path,
    sarif: Path | None,
    html: Path | None,
    markdown: Path | None,
    vex: Path | None,
    junit: Path | None,
) -> None:
    """Write the canonical JSON report plus any requested SARIF / HTML / Markdown /
    OpenVEX / JUnit artifacts."""
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
    if vex is not None:
        _write(vex, get_reporter("vex").render(findings))
        log.info("wrote OpenVEX document: %s", vex)
    if junit is not None:
        _write(junit, build_junit_xml(result.diff, verdict))
        log.info("wrote JUnit report: %s", junit)


def _log_summary(result: PipelineResult, verdict: GateVerdict) -> None:
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
    if verdict.passed:
        log.info("%s", verdict.summary)
    else:
        log.error("%s", verdict.summary)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
@app.command()
def version() -> None:
    """Print the vulnpipe version."""
    log.info("vulnpipe %s", __version__)


@app.command()
def schema(
    kind: Annotated[
        str,
        typer.Argument(help="Which schema to print: config, report, policy, or false-positives."),
    ] = "config",
) -> None:
    """Print a JSON Schema: the targets/scope config, the findings report, or a gate policy."""
    builders = {
        "config": Config.model_json_schema,
        "report": build_report_schema,
        "policy": GatePolicy.model_json_schema,
        "false-positives": FalsePositiveConfig.model_json_schema,
    }
    builder = builders.get(kind)
    if builder is None:
        log.error("Unknown schema kind %r; choose one of: %s", kind, ", ".join(sorted(builders)))
        raise typer.Exit(code=2)
    _emit(json.dumps(builder(), indent=2, ensure_ascii=False) + "\n")


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
    gate_risk_score: Annotated[
        int | None,
        typer.Option(
            "--gate-risk-score",
            min=0,
            max=100,
            help="Also fail on a new finding with a composite risk score at or above this.",
        ),
    ] = None,
    policy: Annotated[
        Path | None,
        typer.Option(
            "--policy",
            dir_okay=False,
            help=(
                "Gate-policy YAML (severity budgets, KEV block, risk threshold); "
                "when given it decides the verdict instead of --gate-severity."
            ),
        ),
    ] = None,
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
    vex: Annotated[
        Path | None,
        typer.Option("--vex", dir_okay=False, help="Also write an OpenVEX document here."),
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
        gate_policy = load_policy(policy) if policy is not None else None
    except (ConfigError, BaselineError, PolicyError, OSError, ValueError, ValidationError) as exc:
        log.error("%s", exc)
        raise typer.Exit(code=2) from exc

    log.info("authorization confirmed; scanning %d target(s) in scope", len(cfg.targets))
    result = run_pipeline(
        cfg,
        authorized=True,
        allowlist=allowlist,
        baseline=base,
        gate_threshold=gate_severity,
        gate_min_risk_score=gate_risk_score,
    )
    verdict: GateVerdict = result.gate
    if gate_policy is not None:
        verdict = evaluate_policy(result.diff, gate_policy)
    _write_reports(
        result,
        verdict,
        output=output,
        sarif=sarif,
        html=html,
        markdown=markdown,
        vex=vex,
        junit=junit,
    )
    _log_summary(result, verdict)

    if not no_gate and verdict.exit_code != 0:
        raise typer.Exit(code=verdict.exit_code)


@app.command()
def plugins() -> None:
    """List third-party scanner and reporter plugins discovered via entry points."""
    registered = loaded_plugins()
    if not registered:
        _emit(
            "no third-party plugins discovered\n"
            f"packages can provide them via the {SCANNER_GROUP!r} and {REPORTER_GROUP!r} "
            "entry-point groups\n"
        )
        return
    _emit("".join(f"{plugin.label}\n" for plugin in registered))


@app.command()
def validate(
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
) -> None:
    """Validate a config and print what would be scanned, without scanning anything."""
    try:
        cfg = load_config(config)
    except (ConfigError, OSError, ValueError, ValidationError) as exc:
        log.error("%s", exc)
        raise typer.Exit(code=2) from exc
    plan = build_scan_plan(cfg)
    _emit(render_plan(plan))
    unset = [name for name in plan.secret_env_names if os.environ.get(name) is None]
    if unset:
        log.warning("required environment variable(s) not set: %s", ", ".join(unset))
    if not plan.is_valid:
        raise typer.Exit(code=1)


@app.command()
def sbom(
    input_path: Annotated[
        Path,
        typer.Option(
            "--input",
            "-i",
            exists=True,
            dir_okay=False,
            help="CycloneDX JSON SBOM to analyze for known-vulnerable components.",
        ),
    ],
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            file_okay=False,
            help="Directory to write sbom.json into (in addition to any stdout render).",
        ),
    ] = None,
    fmt: Annotated[
        str,
        typer.Option("--format", "-f", help="Render format for stdout: any report format."),
    ] = "json",
    no_enrich: Annotated[
        bool,
        typer.Option("--no-enrich", help="Skip EPSS + CISA KEV enrichment (offline / faster)."),
    ] = False,
    cache_dir: Annotated[
        str,
        typer.Option("--cache-dir", help="Directory for the OSV / enrichment response cache."),
    ] = ".cache",
) -> None:
    """Analyze a CycloneDX SBOM against OSV.dev and report vulnerable dependencies.

    Passive supply-chain analysis: it reads the SBOM and queries public advisory
    data, never touching the described software, so it needs no scope or
    authorization.
    """
    try:
        reporter = get_reporter(fmt)
    except KeyError as exc:
        log.error("Unknown format %r; choose one of: %s", fmt, ", ".join(available_formats()))
        raise typer.Exit(code=2) from exc
    try:
        findings = run_sbom_pipeline(input_path, enrich=not no_enrich, cache_dir=cache_dir)
    except SbomError as exc:
        log.error("%s", exc)
        raise typer.Exit(code=2) from exc
    log.info("sbom analysis: %d finding(s) from %s", len(findings), input_path)
    if output is not None:
        json_path = output / "sbom.json"
        _write(json_path, get_reporter("json").render(findings))
        log.info("wrote SBOM findings JSON: %s", json_path)
    _emit(reporter.render(findings))


@app.command()
def report(
    input_path: Annotated[
        Path,
        typer.Option("--input", "-i", exists=True, dir_okay=False, help="Findings JSON to render."),
    ],
    fmt: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Report format: json, html, markdown, csv, prometheus, sarif, or vex.",
        ),
    ] = "html",
) -> None:
    """Render a findings JSON into any report format (HTML, SARIF, OpenVEX, ...) on stdout."""
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


@app.command()
def merge(
    input_paths: Annotated[
        list[Path],
        typer.Option(
            "--input",
            "-i",
            exists=True,
            dir_okay=False,
            help="A findings JSON to merge (repeat the option for each report).",
        ),
    ],
    output: Annotated[
        Path | None,
        typer.Option(
            "--output", "-o", dir_okay=False, help="Also write the merged canonical JSON here."
        ),
    ] = None,
    fmt: Annotated[
        str,
        typer.Option("--format", "-f", help="Render format for stdout: any report format."),
    ] = "json",
) -> None:
    """Merge findings JSONs from separate runs into one deduplicated report.

    Lets independent runs -- a network scan, an SBOM analysis, scans of two
    network segments -- feed a single report, baseline, and gate. Findings
    sharing a fingerprint collapse into the richest instance (the same rule the
    in-pipeline deduplicator applies), and the result is re-prioritized.
    """
    try:
        reporter = get_reporter(fmt)
    except KeyError as exc:
        log.error("Unknown format %r; choose one of: %s", fmt, ", ".join(available_formats()))
        raise typer.Exit(code=2) from exc
    combined: list[Finding] = []
    try:
        for path in input_paths:
            combined.extend(load_findings(path))
    except (OSError, ValueError) as exc:
        log.error("Failed to read findings: %s", exc)
        raise typer.Exit(code=2) from exc
    merged = prioritize(deduplicate(combined))
    log.info(
        "merged %d report(s): %d finding(s) in, %d after dedup",
        len(input_paths),
        len(combined),
        len(merged),
    )
    if output is not None:
        _write(output, get_reporter("json").render(merged))
        log.info("wrote merged findings JSON: %s", output)
    _emit(reporter.render(merged))


@app.command()
def stats(
    input_path: Annotated[
        Path,
        typer.Option(
            "--input", "-i", exists=True, dir_okay=False, help="Findings JSON to summarize."
        ),
    ],
) -> None:
    """Print a terminal summary of a findings JSON: severity, top risks, worst hosts."""
    try:
        findings = load_findings(input_path)
    except (OSError, ValueError) as exc:
        log.error("Failed to read findings from %s: %s", input_path, exc)
        raise typer.Exit(code=2) from exc
    _emit(render_stats(findings))


@app.command()
def badge(
    input_path: Annotated[
        Path,
        typer.Option(
            "--input", "-i", exists=True, dir_okay=False, help="Findings JSON to summarize."
        ),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", dir_okay=False, help="SVG file to write (default stdout)."),
    ] = None,
    label: Annotated[
        str,
        typer.Option("--label", help="Badge label text."),
    ] = "vulnpipe",
) -> None:
    """Render a findings JSON into a shields-style SVG status badge."""
    try:
        findings = load_findings(input_path)
    except (OSError, ValueError) as exc:
        log.error("Failed to read findings from %s: %s", input_path, exc)
        raise typer.Exit(code=2) from exc
    svg = render_badge(findings, label=label)
    if output is not None:
        _write(output, svg)
        log.info("wrote badge: %s", output)
    else:
        _emit(svg)


@app.command()
def notify(
    input_path: Annotated[
        Path,
        typer.Option(
            "--input", "-i", exists=True, dir_okay=False, help="Findings JSON to summarize."
        ),
    ],
    webhook_url_env: Annotated[
        str,
        typer.Option(
            "--webhook-url-env",
            help="Env var holding the Slack-compatible webhook URL (a secret).",
        ),
    ] = "VULNPIPE_WEBHOOK_URL",
) -> None:
    """Post a summary of a findings JSON to a Slack-compatible incoming webhook."""
    url = os.environ.get(webhook_url_env)
    if not url:
        log.error("webhook URL not set; set $%s in the environment", webhook_url_env)
        raise typer.Exit(code=2)
    try:
        findings = load_findings(input_path)
    except (OSError, ValueError) as exc:
        log.error("Failed to read findings from %s: %s", input_path, exc)
        raise typer.Exit(code=2) from exc
    try:
        status = post_webhook(url, findings)
    except NotifyError as exc:
        log.error("%s", exc)  # never logs the URL, which is a secret
        raise typer.Exit(code=1) from exc
    log.info("posted findings summary to webhook (HTTP %d)", status)


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
        str,
        typer.Option("--format", "-f", help="Output format: text, json, markdown, or html."),
    ] = "text",
) -> None:
    """Diff current findings against a baseline (new / persisting / resolved)."""
    if fmt not in {"text", "json", "markdown", "html"}:
        log.error("Unknown diff format %r; choose text, json, markdown, or html", fmt)
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
    elif fmt == "markdown":
        _emit(render_diff_markdown(result))
    elif fmt == "html":
        _emit(render_diff_html(result))
    else:
        _print_diff_text(result)


def _print_policy_text(result: PolicyResult) -> None:
    """Print a compact text summary of a policy verdict to stdout."""
    typer.echo(result.summary)
    for violation in result.violations:
        typer.echo(f"  x {violation.detail}")
        for finding in violation.findings:
            typer.echo(f"      [{finding.severity.value}] {finding.title} ({finding.host})")


@app.command()
def gate(
    current: Annotated[
        Path,
        typer.Option("--current", exists=True, dir_okay=False, help="Current findings JSON."),
    ],
    baseline: Annotated[
        Path | None,
        typer.Option(
            "--baseline",
            dir_okay=False,
            help="Baseline or findings JSON to diff against; omitted = everything is new.",
        ),
    ] = None,
    policy: Annotated[
        Path | None,
        typer.Option(
            "--policy",
            dir_okay=False,
            help="Gate-policy YAML; when omitted the severity/risk options apply.",
        ),
    ] = None,
    gate_severity: Annotated[
        Severity,
        typer.Option("--gate-severity", help="Fail on a new finding at or above this severity."),
    ] = DEFAULT_GATE_SEVERITY,
    gate_risk_score: Annotated[
        int | None,
        typer.Option(
            "--gate-risk-score",
            min=0,
            max=100,
            help="Also fail on a new finding with a composite risk score at or above this.",
        ),
    ] = None,
    fmt: Annotated[
        str, typer.Option("--format", "-f", help="Output format: text or json.")
    ] = "text",
) -> None:
    """Evaluate the CI gate over an existing findings JSON, without rescanning."""
    if fmt not in {"text", "json"}:
        log.error("Unknown gate format %r; choose text or json", fmt)
        raise typer.Exit(code=2)
    try:
        findings = load_findings(current)
        base = _load_baseline_or_findings(baseline) if baseline is not None else Baseline()
        rules = (
            load_policy(policy)
            if policy is not None
            else policy_from_threshold(gate_severity, min_risk_score=gate_risk_score)
        )
    except (PolicyError, BaselineError, OSError, ValueError) as exc:
        log.error("Failed to load gate inputs: %s", exc)
        raise typer.Exit(code=2) from exc
    result = evaluate_policy(diff_findings(findings, base), rules)
    if fmt == "json":
        typer.echo(json.dumps(policy_result_to_payload(result), indent=2, ensure_ascii=False))
    else:
        _print_policy_text(result)
    if result.exit_code != 0:
        raise typer.Exit(code=result.exit_code)


@app.command()
def trend(
    inputs: Annotated[
        list[Path],
        typer.Argument(help="Findings JSON files, oldest first (the time axis)."),
    ],
    fmt: Annotated[
        str, typer.Option("--format", "-f", help="Output format: text or json.")
    ] = "text",
) -> None:
    """Analyze how findings evolve across a chronological series of scan reports."""
    if fmt not in {"text", "json"}:
        log.error("Unknown trend format %r; choose text or json", fmt)
        raise typer.Exit(code=2)
    if not inputs:
        log.error("Provide at least one findings JSON file")
        raise typer.Exit(code=2)
    try:
        snapshots = [(path.stem, load_findings(path)) for path in inputs]
    except (OSError, ValueError) as exc:
        log.error("Failed to load trend inputs: %s", exc)
        raise typer.Exit(code=2) from exc
    result = build_trend(snapshots)
    if fmt == "json":
        typer.echo(json.dumps(trend_to_payload(result), indent=2, ensure_ascii=False))
    else:
        _emit(render_trend_text(result))


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
