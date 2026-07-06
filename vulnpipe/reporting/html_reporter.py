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
from vulnpipe.reporting.remediation import plan_remediations
from vulnpipe.reporting.summary import (
    SEVERITY_DISPLAY_ORDER,
    StandardsSummary,
    finding_owasp,
    finding_owner,
    group_by_host,
    group_by_owner,
    owners_present,
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


#: How many remediation actions the report's "Remediation plan" panel lists.
_REMEDIATION_TOP = 10


# Ranked OWASP bar-chart layout (pixels). Fixed columns -- so the count and the
# category title align across rows regardless of bar length.
_OWASP_ROW_HEIGHT = 28
_OWASP_BAR_HEIGHT = 20
_OWASP_BAR_TOP_PAD = 4
_OWASP_LABEL_WIDTH = 44
_OWASP_MAX_BAR_WIDTH = 200
_OWASP_COUNT_WIDTH = 28
_OWASP_TITLE_WIDTH = 320
_OWASP_GAP = 10


@dataclass(frozen=True)
class OwaspBar:
    """One OWASP category row of the ranked SVG chart, coordinates pre-computed."""

    short: str
    title: str
    count: int
    rect_y: int
    bar_height: int
    width: int
    text_y: int


@dataclass(frozen=True)
class OwaspChart:
    """A ranked horizontal bar chart of the OWASP categories that have findings."""

    width: int
    height: int
    bar_x: int
    count_x: int
    title_x: int
    bars: tuple[OwaspBar, ...]


def build_owasp_chart(standards: StandardsSummary) -> OwaspChart | None:
    """Compute the SVG geometry for a ranked OWASP Top 10 bar chart, or ``None``.

    Only categories with at least one finding appear, ordered by count (descending)
    then OWASP rank, so the most prevalent weakness class leads and ties break
    deterministically. Bars scale to the busiest category. Returns ``None`` when
    nothing maps, letting the template render its empty state.
    """
    present = [(category, count) for category, count in standards.owasp.items() if count]
    if not present:
        return None
    present.sort(key=lambda item: (-item[1], item[0].rank))
    max_count = max(count for _, count in present)
    bar_x = _OWASP_LABEL_WIDTH
    count_x = bar_x + _OWASP_MAX_BAR_WIDTH + _OWASP_GAP
    title_x = count_x + _OWASP_COUNT_WIDTH + _OWASP_GAP
    bars = tuple(
        OwaspBar(
            short=category.short,
            title=category.title,
            count=count,
            rect_y=index * _OWASP_ROW_HEIGHT + _OWASP_BAR_TOP_PAD,
            bar_height=_OWASP_BAR_HEIGHT,
            width=round(_OWASP_MAX_BAR_WIDTH * count / max_count),
            text_y=index * _OWASP_ROW_HEIGHT + _OWASP_BAR_TOP_PAD + _OWASP_BAR_HEIGHT - 5,
        )
        for index, (category, count) in enumerate(present)
    )
    return OwaspChart(
        width=title_x + _OWASP_TITLE_WIDTH,
        height=_OWASP_ROW_HEIGHT * len(present),
        bar_x=bar_x,
        count_x=count_x,
        title_x=title_x,
        bars=bars,
    )


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
    standards = summarize_standards(items)
    actions = plan_remediations(items)
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
        standards=standards,
        owasp_chart=build_owasp_chart(standards),
        finding_owasp=finding_owasp,
        finding_owner=finding_owner,
        owner_groups=group_by_owner(items),
        show_owners=owners_present(items),
        remediations=actions[:_REMEDIATION_TOP],
        remediation_total=len(actions),
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
    "OwaspBar",
    "OwaspChart",
    "SeverityChart",
    "SeverityStyle",
    "build_owasp_chart",
    "build_severity_chart",
    "render_html",
    "risk_css",
]
