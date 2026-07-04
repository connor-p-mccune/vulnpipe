"""Report renderers: JSON, HTML, and SARIF.

Each reporter subclasses :class:`~vulnpipe.reporting.base.BaseReporter` and turns a
list of findings into a serialized report string. JSON is the canonical, lossless
artifact (round-trippable via :func:`report_to_findings`); HTML is the human view;
Markdown drops into a pull-request comment or Slack; CSV drops into a spreadsheet;
Prometheus text feeds observability tooling; SARIF feeds the GitHub code-scanning
dashboard and GitLab the GitLab Vulnerability Report; OpenVEX feeds
exploitability-exchange tooling. All are deterministic for fixed input (the OpenVEX
and GitLab scan timestamps are the documented, spec-mandated exceptions -- see the
respective reporter modules).

:func:`get_reporter` resolves a format name (``"json"`` / ``"html"`` / ``"markdown"``
/ ``"csv"`` / ``"prometheus"`` / ``"sarif"`` / ``"gitlab"`` / ``"vex"``) to a reporter
instance so callers -- e.g. the ``report`` CLI command -- can stay format-agnostic.
"""

from vulnpipe.reporting.badge import badge_value, render_badge
from vulnpipe.reporting.base import BaseReporter
from vulnpipe.reporting.csv_reporter import CsvReporter, render_csv
from vulnpipe.reporting.gitlab_reporter import GitlabReporter, build_gitlab_report, render_gitlab
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
from vulnpipe.reporting.remediation import (
    RemediationAction,
    plan_remediations,
    remediation_to_payload,
    render_remediation_markdown,
    render_remediation_text,
)
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
from vulnpipe.reporting.vex_reporter import VexReporter, build_vex, render_vex

_REPORTERS: dict[str, type[BaseReporter]] = {
    JsonReporter.name: JsonReporter,
    HtmlReporter.name: HtmlReporter,
    MarkdownReporter.name: MarkdownReporter,
    CsvReporter.name: CsvReporter,
    PrometheusReporter.name: PrometheusReporter,
    SarifReporter.name: SarifReporter,
    GitlabReporter.name: GitlabReporter,
    VexReporter.name: VexReporter,
}


def available_formats() -> list[str]:
    """Return the sorted report format names :func:`get_reporter` understands."""
    return sorted(_REPORTERS)


def register_reporter(reporter_cls: type[BaseReporter]) -> type[BaseReporter]:
    """Register a reporter class under its ``name``. Usable as a class decorator.

    This is how third-party report formats join the registry (see
    :mod:`vulnpipe.plugins`); the built-ins above register the same way, just
    statically.
    """
    _REPORTERS[reporter_cls.name] = reporter_cls
    return reporter_cls


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
    "GitlabReporter",
    "HtmlReporter",
    "JsonReporter",
    "MarkdownReporter",
    "PrometheusReporter",
    "RemediationAction",
    "ReportSummary",
    "SarifReporter",
    "StandardsSummary",
    "VexReporter",
    "available_formats",
    "badge_value",
    "build_gitlab_report",
    "build_report",
    "build_report_schema",
    "build_sarif",
    "build_vex",
    "finding_owasp",
    "get_reporter",
    "group_by_host",
    "load_findings",
    "plan_remediations",
    "register_reporter",
    "remediation_to_payload",
    "render_badge",
    "render_csv",
    "render_gitlab",
    "render_html",
    "render_markdown",
    "render_prometheus",
    "render_remediation_markdown",
    "render_remediation_text",
    "render_stats",
    "render_vex",
    "report_to_findings",
    "severity_counts",
    "summarize",
    "summarize_standards",
]
