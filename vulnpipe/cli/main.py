"""``vulnpipe`` command-line interface (Typer).

Thin entry point wiring configuration loading and the authorization/scope guards
to the pipeline. Scanner orchestration is added in a later phase; the ``scan``
command already enforces the authorization hard rules before anything would run.
"""

import logging
from pathlib import Path
from typing import Annotated

import typer

from vulnpipe import __version__
from vulnpipe.core.config import (
    ConfigError,
    ensure_authorized,
    ensure_config_in_scope,
    load_config,
)
from vulnpipe.core.logging import configure_logging, get_logger

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
) -> None:
    """Validate authorization/scope, then run the scan pipeline."""
    try:
        cfg = load_config(config)
        ensure_authorized(authorized=authorized, scope=cfg.scope)
        ensure_config_in_scope(cfg)
    except ConfigError as exc:
        log.error("%s", exc)
        raise typer.Exit(code=2) from exc

    log.info("Authorization confirmed; %d target(s) validated within scope", len(cfg.targets))
    log.warning("Scanner stages are not yet implemented in this scaffold")


@app.command()
def report(
    input_path: Annotated[
        Path,
        typer.Option("--input", "-i", exists=True, dir_okay=False, help="Findings JSON to render."),
    ],
    fmt: Annotated[
        str, typer.Option("--format", "-f", help="Report format: json, html, or sarif.")
    ] = "html",
) -> None:
    """Render a findings file into a report (not yet implemented)."""
    log.warning(
        "report (format=%s) for %s is not yet implemented in this scaffold", fmt, input_path
    )


@app.command()
def diff(
    baseline: Annotated[
        Path,
        typer.Option("--baseline", exists=True, dir_okay=False, help="Baseline findings JSON."),
    ],
    current: Annotated[
        Path, typer.Option("--current", exists=True, dir_okay=False, help="Current findings JSON.")
    ],
) -> None:
    """Diff current findings against a baseline (not yet implemented)."""
    log.warning(
        "diff of %s vs baseline %s is not yet implemented in this scaffold", current, baseline
    )


def main() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":
    main()
