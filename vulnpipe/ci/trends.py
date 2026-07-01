"""Trend analysis across a series of scans.

Given several findings snapshots in chronological order, this stage tracks how the
security posture moves over time: the totals and severity mix at each scan, how many
findings were *introduced* and *resolved* between consecutive scans (matched by the
same stable fingerprint the deduplicator and differ use), and whether the serious
(critical + high) backlog is trending up or down.

Everything here is a pure function -- snapshots in, a :class:`Trend` (or a
JSON-ready payload / plain-text table) out -- and deterministic for fixed input, so
it is trivially unit-testable and safe to snapshot. Rendering deliberately avoids
any wall-clock timestamp; the scan labels supplied by the caller (e.g. filenames)
are the time axis.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
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


__all__ = [
    "ScanPoint",
    "Snapshot",
    "Trend",
    "build_trend",
    "render_trend_text",
    "trend_to_payload",
]
