"""Unit tests for the SVG status badge renderer.

The badge is a pure renderer: assert on the value/color selection, the worst-band
summary, KEV marking, XML escaping, and determinism.
"""

import xml.etree.ElementTree as ET

from vulnpipe.core.models import Finding, Severity
from vulnpipe.processing.normalizer import make_finding
from vulnpipe.reporting.badge import badge_value, render_badge


def _f(title: str, severity: Severity, *, kev: bool = False) -> Finding:
    return make_finding(source="zap", host="h", title=title, severity=severity, kev=kev)


def test_clean_badge_when_no_findings() -> None:
    value, color = badge_value([])
    assert value == "clean"
    assert color == "#2e7d32"


def test_value_lists_two_worst_bands_with_ellipsis() -> None:
    findings = [
        _f("c", Severity.CRITICAL),
        _f("h1", Severity.HIGH),
        _f("h2", Severity.HIGH),
        _f("m", Severity.MEDIUM),
    ]
    value, color = badge_value(findings)
    assert value == "1 critical, 2 high, …"
    assert color == "#7b1fa2"  # the critical band's report color


def test_value_without_overflow_has_no_ellipsis() -> None:
    value, color = badge_value([_f("h", Severity.HIGH), _f("l", Severity.LOW)])
    assert value == "1 high, 1 low"
    assert color == "#c62828"


def test_kev_marker_prefixes_value() -> None:
    value, _color = badge_value([_f("exploited", Severity.MEDIUM, kev=True)])
    assert value.startswith("! ")


def test_render_is_valid_svg_with_title_and_texts() -> None:
    svg = render_badge([_f("h", Severity.HIGH)])
    root = ET.fromstring(svg)
    assert root.tag.endswith("svg")
    texts = [el.text for el in root.iter() if el.tag.endswith("text")]
    assert "vulnpipe" in texts
    assert "1 high" in texts
    title = next(el.text for el in root.iter() if el.tag.endswith("title"))
    assert title == "vulnpipe: 1 high"


def test_label_is_escaped_not_injected() -> None:
    svg = render_badge([], label='x"><script>alert(1)</script>')
    assert "<script>" not in svg
    ET.fromstring(svg)  # still well-formed XML


def test_badge_width_grows_with_text() -> None:
    short = ET.fromstring(render_badge([], label="a"))
    long = ET.fromstring(render_badge([], label="a-much-longer-label"))
    assert int(long.attrib["width"]) > int(short.attrib["width"])


def test_render_is_deterministic() -> None:
    findings = [_f("h", Severity.HIGH), _f("c", Severity.CRITICAL, kev=True)]
    assert render_badge(findings) == render_badge(findings)
