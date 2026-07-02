"""SVG status badge: a scan's posture as a shields-style README badge.

Renders findings into a small, self-contained, flat-style SVG badge -- the
artifact a repository embeds next to its build badge to surface the latest scan
result at a glance. The value text summarizes the worst outstanding severities
(``1 critical, 5 high``) or reads ``clean``, and the badge is colored by the
worst severity band using the same palette as the HTML report, plus an
exclamation marker when anything is known-exploited.

Pure and deterministic like every renderer: findings in, an SVG string out, with
no timestamp and a documented fixed-width text approximation (no font metrics),
so the same findings always produce a byte-identical badge. All text is
XML-escaped; nothing from scanner output is executed or styled.
"""

from collections.abc import Iterable
from xml.sax.saxutils import escape

from vulnpipe.core.models import Finding, Severity
from vulnpipe.reporting.html_reporter import SEVERITY_STYLES
from vulnpipe.reporting.summary import SEVERITY_DISPLAY_ORDER, severity_counts

#: Color of the label (left) segment and of a clean (no findings) badge.
_LABEL_COLOR = "#555"
_CLEAN_COLOR = "#2e7d32"
#: Approximate character advance for the badge font stack at 11px. A documented
#: approximation: SVG viewers do not report text metrics, and a fixed factor keeps
#: the output deterministic everywhere.
_CHAR_WIDTH = 6.5
_PADDING = 10
_HEIGHT = 20
#: At most this many severity bands appear in the value text (worst first).
_MAX_BANDS = 2


def _segment_width(text: str) -> int:
    return round(len(text) * _CHAR_WIDTH) + _PADDING


def badge_value(findings: list[Finding]) -> tuple[str, str]:
    """The badge's value text and color for ``findings``.

    The text lists the two worst non-empty severity bands (``1 critical, 5 high``),
    prefixed with ``!`` when any finding is known-exploited; with no findings at
    all it reads ``clean``. The color is the worst band's report color.
    """
    counts = severity_counts(findings)
    nonzero = [
        (severity, counts[severity]) for severity in SEVERITY_DISPLAY_ORDER if counts[severity]
    ]
    if not nonzero:
        return "clean", _CLEAN_COLOR
    parts = [f"{count} {severity.value}" for severity, count in nonzero[:_MAX_BANDS]]
    text = ", ".join(parts)
    if len(nonzero) > _MAX_BANDS:
        text += ", …"
    if any(finding.kev for finding in findings):
        text = f"! {text}"
    worst: Severity = nonzero[0][0]
    return text, SEVERITY_STYLES[worst].color


def render_badge(findings: Iterable[Finding], *, label: str = "vulnpipe") -> str:
    """Render ``findings`` into a flat-style SVG badge string."""
    items = list(findings)
    value, color = badge_value(items)
    label_width = _segment_width(label)
    value_width = _segment_width(value)
    total = label_width + value_width
    title = f"{label}: {value}"

    def _text(content: str, x_center: float) -> str:
        return (
            f'<text x="{x_center}" y="14" fill="#fff" text-anchor="middle" '
            f'font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">'
            f"{escape(content)}</text>"
        )

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="{_HEIGHT}" '
        f'role="img" aria-label="{escape(title, {'"': "&quot;"})}">\n'
        f"  <title>{escape(title)}</title>\n"
        f'  <rect width="{label_width}" height="{_HEIGHT}" fill="{_LABEL_COLOR}"/>\n'
        f'  <rect x="{label_width}" width="{value_width}" height="{_HEIGHT}" fill="{color}"/>\n'
        f"  {_text(label, label_width / 2)}\n"
        f"  {_text(value, label_width + value_width / 2)}\n"
        f"</svg>\n"
    )


__all__ = ["badge_value", "render_badge"]
