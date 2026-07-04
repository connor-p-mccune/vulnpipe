"""Trend analysis across a series of scans.

Given several findings snapshots in chronological order, this stage tracks how the
security posture moves over time: the totals and severity mix at each scan, how many
findings were *introduced* and *resolved* between consecutive scans (matched by the
same stable fingerprint the deduplicator and differ use), and whether the serious
(critical + high) backlog is trending up or down.

Everything here is a pure function -- snapshots in, a :class:`Trend` (or a
JSON-ready payload / plain-text table / self-contained HTML page with an inline SVG
chart) out -- and deterministic for fixed input, so it is trivially unit-testable
and safe to snapshot. Rendering deliberately avoids any wall-clock timestamp; the
scan labels supplied by the caller (e.g. filenames) are the time axis.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from html import escape
from typing import Any

from vulnpipe.core.models import Finding, Severity
from vulnpipe.reporting.summary import SEVERITY_DISPLAY_ORDER, severity_counts

#: A labeled snapshot: the caller's label (e.g. a filename) plus that scan's findings.
Snapshot = tuple[str, Sequence[Finding]]


@dataclass(frozen=True)
class ScanPoint:
    """The metrics for a single scan in the series."""

    label: str
    total: int
    by_severity: dict[Severity, int]
    kev: int
    #: Findings introduced since the previous scan (all findings for the first scan).
    introduced: int
    #: Findings resolved since the previous scan (0 for the first scan).
    resolved: int

    @property
    def serious(self) -> int:
        """Count of critical + high findings (the backlog the gate cares about)."""
        return self.by_severity[Severity.CRITICAL] + self.by_severity[Severity.HIGH]


@dataclass(frozen=True)
class Trend:
    """A trend across a chronological series of scans."""

    points: tuple[ScanPoint, ...]

    @property
    def direction(self) -> str:
        """``improving`` / ``worsening`` / ``flat`` by the serious-backlog delta."""
        if len(self.points) < 2:
            return "flat"
        delta = self.points[-1].serious - self.points[0].serious
        if delta > 0:
            return "worsening"
        if delta < 0:
            return "improving"
        return "flat"

    @property
    def net_serious_change(self) -> int:
        """Change in the critical + high backlog from the first scan to the last."""
        if not self.points:
            return 0
        return self.points[-1].serious - self.points[0].serious


def _fingerprints(findings: Iterable[Finding]) -> set[str]:
    return {finding.fingerprint for finding in findings}


def build_trend(snapshots: Sequence[Snapshot]) -> Trend:
    """Build a :class:`Trend` from labeled findings snapshots in chronological order.

    ``introduced`` / ``resolved`` at each step compare the current scan's fingerprints
    against the immediately preceding scan's; the first scan counts every finding as
    introduced and nothing resolved.
    """
    points: list[ScanPoint] = []
    previous: set[str] = set()
    for index, (label, findings) in enumerate(snapshots):
        current = _fingerprints(findings)
        introduced = len(current) if index == 0 else len(current - previous)
        resolved = 0 if index == 0 else len(previous - current)
        points.append(
            ScanPoint(
                label=label,
                total=len(findings),
                by_severity=severity_counts(findings),
                kev=sum(1 for finding in findings if finding.kev),
                introduced=introduced,
                resolved=resolved,
            )
        )
        previous = current
    return Trend(points=tuple(points))


def trend_to_payload(trend: Trend) -> dict[str, Any]:
    """Serialize a :class:`Trend` into a deterministic JSON-ready mapping."""
    return {
        "direction": trend.direction,
        "net_serious_change": trend.net_serious_change,
        "scans": [
            {
                "label": point.label,
                "total": point.total,
                "by_severity": {
                    severity.value: point.by_severity[severity]
                    for severity in SEVERITY_DISPLAY_ORDER
                },
                "kev": point.kev,
                "introduced": point.introduced,
                "resolved": point.resolved,
            }
            for point in trend.points
        ],
    }


_COLUMNS: tuple[tuple[str, str], ...] = (
    ("scan", "label"),
    ("total", "total"),
    ("crit", "critical"),
    ("high", "high"),
    ("kev", "kev"),
    ("+new", "introduced"),
    ("-resolved", "resolved"),
)


def _cell(point: ScanPoint, key: str) -> str:
    if key == "label":
        return point.label
    if key in ("critical", "high"):
        return str(point.by_severity[Severity(key)])
    return str(getattr(point, key))


def render_trend_text(trend: Trend) -> str:
    """Render a :class:`Trend` as a fixed-width plain-text table plus a summary line."""
    headers = [header for header, _ in _COLUMNS]
    rows = [[_cell(point, key) for _, key in _COLUMNS] for point in trend.points]
    widths = [
        max(len(headers[col]), *(len(row[col]) for row in rows)) if rows else len(headers[col])
        for col in range(len(headers))
    ]

    def _format(cells: Sequence[str]) -> str:
        # First column left-justified (labels); the numeric columns right-justified.
        parts = [cells[0].ljust(widths[0])]
        parts += [cells[col].rjust(widths[col]) for col in range(1, len(cells))]
        return "  ".join(parts).rstrip()

    lines = [_format(headers)]
    lines.extend(_format(row) for row in rows)
    sign = "+" if trend.net_serious_change > 0 else ""
    lines.append("")
    lines.append(
        f"risk trend: {trend.direction} "
        f"(critical+high {sign}{trend.net_serious_change} across {len(trend.points)} scan(s))"
    )
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# HTML rendering (a self-contained, shareable trend page)
# --------------------------------------------------------------------------- #
# Severity -> CSS class for the stacked-bar segments (mirrors the report palette).
_SEVERITY_CSS: dict[Severity, str] = {
    Severity.CRITICAL: "sev-critical",
    Severity.HIGH: "sev-high",
    Severity.MEDIUM: "sev-medium",
    Severity.LOW: "sev-low",
    Severity.INFORMATIONAL: "sev-informational",
}

# Stacked-bar chart layout (pixels).
_COL_WIDTH = 46
_COL_GAP = 22
_PLOT_HEIGHT = 220
_TOP_PAD = 12
_LEFT_PAD = 14
_LABEL_AREA = 46


@dataclass(frozen=True)
class TrendSegment:
    """One severity segment of a scan's stacked bar, coordinates pre-computed."""

    css_class: str
    x: int
    y: int
    width: int
    height: int


@dataclass(frozen=True)
class TrendColumn:
    """One scan's stacked bar: its label position, total, and severity segments."""

    label: str
    total: int
    center_x: int
    total_y: int
    segments: tuple[TrendSegment, ...]


@dataclass(frozen=True)
class TrendChart:
    """A stacked-bar chart of the severity mix across the scan series."""

    width: int
    height: int
    baseline_y: int
    columns: tuple[TrendColumn, ...]


def build_trend_chart(trend: Trend) -> TrendChart:
    """Compute the SVG geometry for a stacked severity bar chart across scans.

    Each scan is one column; severity bands stack least-severe at the bottom to the
    shared height scale (the busiest scan fills the plot). Pure and deterministic --
    all-integer geometry from the trend's counts -- so it is unit-testable without
    rendering, exactly like the report's severity chart.
    """
    points = trend.points
    baseline_y = _TOP_PAD + _PLOT_HEIGHT
    max_total = max((point.total for point in points), default=0) or 1
    columns: list[TrendColumn] = []
    for index, point in enumerate(points):
        x = _LEFT_PAD + index * (_COL_WIDTH + _COL_GAP)
        running_y = baseline_y
        segments: list[TrendSegment] = []
        for severity in reversed(SEVERITY_DISPLAY_ORDER):
            count = point.by_severity[severity]
            if not count:
                continue
            height = round(_PLOT_HEIGHT * count / max_total)
            running_y -= height
            segments.append(
                TrendSegment(
                    css_class=_SEVERITY_CSS[severity],
                    x=x,
                    y=running_y,
                    width=_COL_WIDTH,
                    height=height,
                )
            )
        columns.append(
            TrendColumn(
                label=point.label,
                total=point.total,
                center_x=x + _COL_WIDTH // 2,
                total_y=running_y - 6,
                segments=tuple(segments),
            )
        )
    width = _LEFT_PAD * 2 + len(points) * (_COL_WIDTH + _COL_GAP)
    return TrendChart(
        width=max(width, 160),
        height=baseline_y + _LABEL_AREA,
        baseline_y=baseline_y,
        columns=tuple(columns),
    )


_TREND_HTML_STYLE = """
body { font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  margin: 2rem; color: #1a1a1a; }
h1 { font-size: 1.4rem; margin-bottom: .25rem; }
h2 { margin-top: 1.75rem; font-size: 1.1rem; }
.direction { font-size: 1rem; font-weight: 600; }
.direction.improving { color: #2e7d32; }
.direction.worsening { color: #c62828; }
.direction.flat { color: #555; }
svg { border: 1px solid #e0e0e0; border-radius: 8px; background: #fff; }
.axis { stroke: #cfcfcf; stroke-width: 1; }
.col-label { font-size: 11px; fill: #333; }
.col-total { font-size: 11px; fill: #333; font-weight: 600; }
.sev-critical { fill: #7b1fa2; } .sev-high { fill: #c62828; }
.sev-medium { fill: #ef6c00; } .sev-low { fill: #f9a825; }
.sev-informational { fill: #1565c0; }
.legend { display: flex; flex-wrap: wrap; gap: .75rem; margin: .5rem 0 0; font-size: .85rem; }
.legend span { display: inline-flex; align-items: center; gap: .3rem; }
.swatch { width: .8rem; height: .8rem; border-radius: 2px; display: inline-block; }
table { border-collapse: collapse; width: 100%; margin-top: .75rem; }
th, td { text-align: right; padding: .35rem .6rem; border-bottom: 1px solid #e0e0e0;
  font-size: .9rem; font-variant-numeric: tabular-nums; }
th:first-child, td:first-child { text-align: left; }
th { background: #fafafa; }
""".strip()

# (label, ScanPoint attribute or severity) for the HTML metrics table.
_HTML_COLUMNS: tuple[tuple[str, str], ...] = (
    ("Scan", "label"),
    ("Total", "total"),
    ("Critical", "critical"),
    ("High", "high"),
    ("KEV", "kev"),
    ("+ New", "introduced"),
    ("- Resolved", "resolved"),
)


def _legend() -> str:
    swatches = "".join(
        f'<span><span class="swatch {_SEVERITY_CSS[severity]}" '
        f'style="background:{color}"></span>{severity.value}</span>'
        for severity, color in (
            (Severity.CRITICAL, "#7b1fa2"),
            (Severity.HIGH, "#c62828"),
            (Severity.MEDIUM, "#ef6c00"),
            (Severity.LOW, "#f9a825"),
            (Severity.INFORMATIONAL, "#1565c0"),
        )
    )
    return f'<div class="legend">{swatches}</div>'


def _chart_svg(chart: TrendChart) -> str:
    parts = [
        f'<svg width="{chart.width}" height="{chart.height}" role="img" '
        f'aria-label="Findings by severity across scans">',
        f'<line class="axis" x1="0" y1="{chart.baseline_y}" '
        f'x2="{chart.width}" y2="{chart.baseline_y}"></line>',
    ]
    for column in chart.columns:
        for segment in column.segments:
            parts.append(
                f'<rect class="{segment.css_class}" x="{segment.x}" y="{segment.y}" '
                f'width="{segment.width}" height="{segment.height}"></rect>'
            )
        if column.total:
            parts.append(
                f'<text class="col-total" x="{column.center_x}" y="{column.total_y}" '
                f'text-anchor="middle">{column.total}</text>'
            )
        label = escape(column.label[:10])
        parts.append(
            f'<text class="col-label" x="{column.center_x}" y="{chart.baseline_y + 16}" '
            f'text-anchor="middle">{label}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def _html_cell(point: ScanPoint, key: str) -> str:
    if key == "label":
        return escape(point.label)
    if key in ("critical", "high"):
        return str(point.by_severity[Severity(key)])
    return str(getattr(point, key))


def render_trend_html(trend: Trend, *, title: str = "vulnpipe security trend") -> str:
    """Render a :class:`Trend` as a self-contained, shareable HTML page.

    A stacked severity bar chart across the scan series, a direction verdict, a
    legend, and a per-scan metrics table. Deterministic for fixed input (no
    timestamp; the caller's scan labels are the time axis) and fully HTML-escaped,
    so it is safe to publish as a build artifact.
    """
    chart = build_trend_chart(trend)
    sign = "+" if trend.net_serious_change > 0 else ""
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{escape(title)}</title>",
        f"<style>{_TREND_HTML_STYLE}</style>",
        "</head>",
        "<body>",
        f"<h1>{escape(title)}</h1>",
        (
            f'<p class="direction {trend.direction}">Risk trend: {trend.direction} '
            f"(critical+high {sign}{trend.net_serious_change} across "
            f"{len(trend.points)} scan(s))</p>"
        ),
        _chart_svg(chart),
        _legend(),
        "<h2>Per-scan metrics</h2>",
        "<table><thead><tr>",
        "".join(f"<th>{escape(header)}</th>" for header, _ in _HTML_COLUMNS),
        "</tr></thead><tbody>",
    ]
    for point in trend.points:
        cells = "".join(f"<td>{_html_cell(point, key)}</td>" for _, key in _HTML_COLUMNS)
        parts.append(f"<tr>{cells}</tr>")
    parts.extend(["</tbody></table>", "</body>", "</html>", ""])
    return "\n".join(parts)


__all__ = [
    "ScanPoint",
    "Snapshot",
    "Trend",
    "TrendChart",
    "TrendColumn",
    "TrendSegment",
    "build_trend",
    "build_trend_chart",
    "render_trend_html",
    "render_trend_text",
    "trend_to_payload",
]
