"""Prometheus metrics report renderer.

Emits the findings as Prometheus text-exposition-format gauges, so a scan can feed
observability tooling: drop the output into the node_exporter *textfile collector*,
push it to a Pushgateway, or scrape it directly. This turns a point-in-time scan into
time-series data -- findings by severity, known-exploited count, and peak risk -- that
a dashboard can chart and alert on.

Like the other reporters it is pure and **deterministic for fixed input**: metric
families appear in a fixed order, per-severity series follow the fixed severity order,
per-source series are sorted, and no timestamp is embedded (Prometheus stamps samples
at scrape/push time). Label values are escaped per the exposition format so scanner
data can never break the output.
"""

from collections.abc import Iterable

from vulnpipe.core.models import Finding
from vulnpipe.processing.ownership import finding_owner
from vulnpipe.reporting.base import BaseReporter
from vulnpipe.reporting.summary import (
    SEVERITY_DISPLAY_ORDER,
    count_hosts,
    severity_counts,
    summarize_standards,
)

_Sample = tuple[dict[str, str], int]


def _escape_label(value: str) -> str:
    """Escape a Prometheus label value (backslash, double-quote, newline)."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _family(name: str, help_text: str, samples: Iterable[_Sample]) -> list[str]:
    """Render one metric family: a HELP line, a TYPE line, then its samples."""
    lines = [f"# HELP {name} {help_text}", f"# TYPE {name} gauge"]
    for labels, value in samples:
        if labels:
            label_str = ",".join(f'{key}="{_escape_label(val)}"' for key, val in labels.items())
            lines.append(f"{name}{{{label_str}}} {value}")
        else:
            lines.append(f"{name} {value}")
    return lines


def render_prometheus(findings: Iterable[Finding]) -> str:
    """Render ``findings`` into a Prometheus text-exposition-format metrics string."""
    items = list(findings)
    counts = severity_counts(items)

    source_counts: dict[str, int] = {}
    for finding in items:
        source_counts[finding.source] = source_counts.get(finding.source, 0) + 1

    lines: list[str] = []
    lines += _family(
        "vulnpipe_findings_total",
        "Number of findings by severity.",
        [({"severity": severity.value}, counts[severity]) for severity in SEVERITY_DISPLAY_ORDER],
    )
    lines += _family(
        "vulnpipe_findings_by_source_total",
        "Number of findings by scanner source.",
        [({"source": source}, source_counts[source]) for source in sorted(source_counts)],
    )
    lines += _family(
        "vulnpipe_known_exploited_total",
        "Findings whose CVE is in the CISA KEV (known-exploited) catalog.",
        [({}, sum(1 for finding in items if finding.kev))],
    )
    standards = summarize_standards(items)
    lines += _family(
        "vulnpipe_owasp_top10_total",
        "Findings mapped to each OWASP Top 10 2021 category (by short code).",
        [({"category": category.short}, count) for category, count in standards.owasp.items()],
    )
    lines += _family(
        "vulnpipe_cwe_top25_total",
        "Findings citing a 2023 CWE Top 25 Most Dangerous Weakness.",
        [({}, standards.cwe_top_25)],
    )
    lines += _family(
        "vulnpipe_hosts_total",
        "Distinct hosts with at least one finding.",
        [({}, count_hosts(items))],
    )
    lines += _family(
        "vulnpipe_max_risk_score",
        "Highest composite risk score across findings (0-100).",
        [({}, max((finding.risk_score for finding in items), default=0))],
    )
    # Per-owner counts, emitted only when ownership is configured so a report without
    # owners stays byte-identical (no empty metric family).
    owner_counts: dict[str, int] = {}
    for finding in items:
        owner = finding_owner(finding)
        if owner is not None:
            owner_counts[owner] = owner_counts.get(owner, 0) + 1
    if owner_counts:
        lines += _family(
            "vulnpipe_findings_by_owner_total",
            "Findings by owning team/queue (present only when ownership is configured).",
            [({"owner": owner}, owner_counts[owner]) for owner in sorted(owner_counts)],
        )
    return "\n".join(lines) + "\n"


class PrometheusReporter(BaseReporter):
    """Render findings into deterministic Prometheus text-exposition metrics."""

    name = "prometheus"

    def render(self, findings: list[Finding]) -> str:
        return render_prometheus(findings)


__all__ = [
    "PrometheusReporter",
    "render_prometheus",
]
