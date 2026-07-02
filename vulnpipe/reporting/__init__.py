"""Report renderers: JSON, HTML, and SARIF.

Each reporter subclasses :class:`~vulnpipe.reporting.base.BaseReporter` and turns a
list of findings into a serialized report string. JSON is the canonical, lossless
artifact (round-trippable via :func:`report_to_findings`); HTML is the human view;
Markdown drops into a pull-request comment or Slack; CSV drops into a spreadsheet;
Prometheus text feeds observability tooling; SARIF feeds code-scanning dashboards.
All are deterministic for fixed input.

:func:`get_reporter` resolves a format name (``"json"`` / ``"html"`` / ``"markdown"``
/ ``"csv"`` / ``"prometheus"`` / ``"sarif"``) to a reporter instance so callers --
e.g. the ``report`` CLI command -- can stay format-agnostic.
"""

from vulnpipe.reporting.badge import badge_value, render_badge
from vulnpipe.reporting.base import BaseReporter
from vulnpipe.reporting.csv_reporter import CsvReporter, render_csv
from vulnpipe.reporting.html_reporter import HtmlReporter, render_html
from vulnpipe.reporting.json_reporter import (
    REPORT_SCHEMA_VERSION,
    JsonReporter,
    build_report,
    build_report_schema,
    load_findings,
    report_to_findings,
)
from vulnpipe.reporting.markdown_reporter import MarkdownReporter, render_markdown
from vulnpipe.reporting.prometheus_reporter import PrometheusReporter, render_prometheus
from vulnpipe.reporting.sarif_reporter import SarifReporter, build_sarif
from vulnpipe.reporting.stats import render_stats
from vulnpipe.reporting.summary import (
    SEVERITY_DISPLAY_ORDER,
    ReportSummary,
    StandardsSummary,
    finding_owasp,
    group_by_host,
    severity_counts,
    summarize,
    summarize_standards,
)

_REPORTERS: dict[str, type[BaseReporter]] = {
    JsonReporter.name: JsonReporter,
    HtmlReporter.name: HtmlReporter,
    MarkdownReporter.name: MarkdownReporter,
    CsvReporter.name: CsvReporter,
    PrometheusReporter.name: PrometheusReporter,
    SarifReporter.name: SarifReporter,
}


def available_formats() -> list[str]:
    """Return the sorted report format names :func:`get_reporter` understands."""
    return sorted(_REPORTERS)


def get_reporter(fmt: str) -> BaseReporter:
    """Return a reporter instance for ``fmt`` (``json`` / ``html`` / ``sarif``).

    Raises :class:`KeyError` for an unknown format, naming the available ones.
    """
    try:
        reporter_cls = _REPORTERS[fmt]
    except KeyError as exc:
        raise KeyError(
            f"Unknown report format {fmt!r}; available: {', '.join(available_formats())}"
        ) from exc
    return reporter_cls()


__all__ = [
    "REPORT_SCHEMA_VERSION",
    "SEVERITY_DISPLAY_ORDER",
    "BaseReporter",
    "CsvReporter",
    "HtmlReporter",
    "JsonReporter",
    "MarkdownReporter",
    "PrometheusReporter",
    "ReportSummary",
    "SarifReporter",
    "StandardsSummary",
    "available_formats",
    "badge_value",
    "build_report",
    "build_report_schema",
    "build_sarif",
    "finding_owasp",
    "get_reporter",
    "group_by_host",
    "load_findings",
    "render_badge",
    "render_csv",
    "render_html",
    "render_markdown",
    "render_prometheus",
    "render_stats",
    "report_to_findings",
    "severity_counts",
    "summarize",
    "summarize_standards",
]
