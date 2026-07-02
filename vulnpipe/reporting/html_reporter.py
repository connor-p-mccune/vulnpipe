"""HTML report renderer.

Renders a prioritized, human-readable report from the Jinja2 templates in
``reporting/templates/``. The page has four parts: a summary with severity counts,
an inline SVG severity chart, a per-host breakdown, and a sortable findings table
(client-side column sorting, no external assets).

The view model is built here so the template stays declarative: severity-bar
geometry is computed by :func:`build_severity_chart` (a pure function, unit-tested
without rendering) and the per-host grouping comes from
:mod:`vulnpipe.reporting.summary`. Output is deterministic for fixed input -- no
timestamp is embedded -- and HTML-escaped throughout (autoescaping is on), so even
scanner evidence such as a reflected ``<script>`` payload is rendered as inert text
rather than live markup.
"""

from collections.abc import Iterable
from dataclasses import dataclass

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

from vulnpipe import __version__
from vulnpipe.core.models import Finding, Severity
from vulnpipe.reporting.base import BaseReporter
from vulnpipe.reporting.summary import (
    SEVERITY_DISPLAY_ORDER,
    finding_owasp,
    group_by_host,
    severity_counts,
    summarize,
    summarize_standards,
)


@dataclass(frozen=True)
class SeverityStyle:
    """Display label, chart/badge color, and CSS class for one severity band."""

    label: str
    color: str
    css_class: str


#: Per-severity presentation, keyed by :class:`Severity`. Shared by the summary
#: badges, the per-host breakdown, and the findings table.
SEVERITY_STYLES: dict[Severity, SeverityStyle] = {
    Severity.CRITICAL: SeverityStyle("Critical", "#7b1fa2", "sev-critical"),
    Severity.HIGH: SeverityStyle("High", "#c62828", "sev-high"),
    Severity.MEDIUM: SeverityStyle("Medium", "#ef6c00", "sev-medium"),
    Severity.LOW: SeverityStyle("Low", "#f9a825", "sev-low"),
    Severity.INFORMATIONAL: SeverityStyle("Informational", "#1565c0", "sev-informational"),
}

# Inline SVG bar-chart layout (pixels).
_ROW_HEIGHT = 30
_BAR_HEIGHT = 22
_BAR_TOP_PAD = 4
_LABEL_WIDTH = 120
_MAX_BAR_WIDTH = 320
_COUNT_GAP = 8


@dataclass(frozen=True)
class ChartBar:
    """One severity row of the SVG chart, with all coordinates pre-computed."""

    label: str
    count: int
    color: str
    rect_y: int
    bar_height: int
    width: int
    text_y: int
    count_x: int


@dataclass(frozen=True)
class SeverityChart:
    """A horizontal severity bar chart sized to its rows."""

    width: int
    height: int
    bar_x: int
    bars: tuple[ChartBar, ...]


# Risk-score band thresholds, mapped onto the shared severity color classes so the
# risk badge reads on the same palette as everything else in the report.
_RISK_BANDS: tuple[tuple[int, str], ...] = (
    (90, "sev-critical"),
    (70, "sev-high"),
    (40, "sev-medium"),
    (10, "sev-low"),
    (0, "sev-informational"),
)


def risk_css(score: int) -> str:
    """Return the CSS severity class coloring a risk-score badge for ``score``."""
    for floor, css_class in _RISK_BANDS:
        if score >= floor:
            return css_class
    return "sev-informational"


def build_severity_chart(counts: dict[Severity, int]) -> SeverityChart:
    """Compute the SVG geometry for a severity bar chart from ``counts``.

    Bars are scaled to the largest count so the busiest severity fills the track;
    when every count is zero all bars have zero width. Severities appear in the
    fixed display order, so the chart is deterministic for fixed input.
    """
    max_count = max(counts.values(), default=0)
    bars = []
    for index, severity in enumerate(SEVERITY_DISPLAY_ORDER):
        count = counts[severity]
        width = round(_MAX_BAR_WIDTH * count / max_count) if max_count else 0
        rect_y = index * _ROW_HEIGHT + _BAR_TOP_PAD
        style = SEVERITY_STYLES[severity]
        bars.append(
            ChartBar(
                label=style.label,
                count=count,
                color=style.color,
                rect_y=rect_y,
                bar_height=_BAR_HEIGHT,
                width=width,
                text_y=rect_y + _BAR_HEIGHT - 6,
                count_x=_LABEL_WIDTH + width + _COUNT_GAP,
            )
        )
    return SeverityChart(
        width=_LABEL_WIDTH + _MAX_BAR_WIDTH + 48,
        height=_ROW_HEIGHT * len(SEVERITY_DISPLAY_ORDER),
        bar_x=_LABEL_WIDTH,
        bars=tuple(bars),
    )


def _environment() -> Environment:
    """Build the Jinja2 environment that loads the packaged report templates."""
    return Environment(
        loader=PackageLoader("vulnpipe.reporting", "templates"),
        autoescape=select_autoescape(["html", "xml", "j2"]),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_html(findings: Iterable[Finding]) -> str:
    """Render ``findings`` into the full HTML report string."""
    items = list(findings)
    counts = severity_counts(items)
    template = _environment().get_template("report.html.j2")
    return template.render(
        tool_name="vulnpipe",
        tool_version=__version__,
        summary=summarize(items),
        severity_order=SEVERITY_DISPLAY_ORDER,
        styles=SEVERITY_STYLES,
        chart=build_severity_chart(counts),
        host_groups=group_by_host(items),
        findings=items,
        kev_count=sum(1 for finding in items if finding.kev),
        risk_css=risk_css,
        standards=summarize_standards(items),
        finding_owasp=finding_owasp,
    )


class HtmlReporter(BaseReporter):
    """Render findings into a self-contained, deterministic HTML report."""

    name = "html"

    def render(self, findings: list[Finding]) -> str:
        return render_html(findings)


__all__ = [
    "SEVERITY_STYLES",
    "ChartBar",
    "HtmlReporter",
    "SeverityChart",
    "SeverityStyle",
    "build_severity_chart",
    "render_html",
    "risk_css",
]
