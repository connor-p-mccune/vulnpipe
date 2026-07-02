"""CSV report renderer.

Emits one row per finding as RFC 4180 CSV -- the format that drops straight into a
spreadsheet, a pivot table, or a data-frame for ad-hoc triage and metrics. Columns
mirror the finding model's field names (plus the computed ``fingerprint`` /
``risk_score``) so the CSV lines up with the canonical JSON.

Like the other reporters it is pure and **deterministic for fixed input**: findings
are emitted in the order given (the prioritized order), the column order is fixed, a
``\\n`` line terminator is used on every platform, and no wall-clock timestamp is
embedded. List fields (CVE / CWE ids) are joined with ``;`` so each finding stays a
single row, and the ``csv`` module quotes any value containing a comma, quote, or
newline.
"""

import csv
import io
from collections.abc import Iterable

from vulnpipe.core.models import Finding
from vulnpipe.reporting.base import BaseReporter
from vulnpipe.reporting.summary import finding_owasp

#: Fixed column order. Mirrors the finding model (plus the computed fingerprint and
#: risk score) so a CSV export lines up with the canonical JSON report.
_COLUMNS: tuple[str, ...] = (
    "fingerprint",
    "severity",
    "risk_score",
    "source",
    "host",
    "port",
    "title",
    "cvss_score",
    "epss_score",
    "kev",
    "cve_ids",
    "cwe_ids",
    "owasp",
    "plugin_id",
    "confidence",
    "url",
)


def _cell(value: object) -> str:
    """Render one field as a CSV cell value (``None`` -> empty; tuples -> ``;``-joined)."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, tuple):
        return ";".join(str(item) for item in value)
    return str(value)


def _row(finding: Finding) -> list[str]:
    values: dict[str, object] = {
        "fingerprint": finding.fingerprint,
        "severity": finding.severity.value,
        "risk_score": finding.risk_score,
        "source": finding.source,
        "host": finding.host,
        "port": finding.port,
        "title": finding.title,
        "cvss_score": finding.cvss_score,
        "epss_score": finding.epss_score,
        "kev": finding.kev,
        "cve_ids": finding.cve_ids,
        "cwe_ids": finding.cwe_ids,
        "owasp": tuple(category.short for category in finding_owasp(finding)),
        "plugin_id": finding.plugin_id,
        "confidence": finding.confidence.value if finding.confidence is not None else None,
        "url": finding.metadata.get("url"),
    }
    return [_cell(values[column]) for column in _COLUMNS]


def render_csv(findings: Iterable[Finding]) -> str:
    """Render ``findings`` into a deterministic RFC 4180 CSV string (header + rows)."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(_COLUMNS)
    for finding in findings:
        writer.writerow(_row(finding))
    return buffer.getvalue()


class CsvReporter(BaseReporter):
    """Render findings into a deterministic CSV report (one row per finding)."""

    name = "csv"

    def render(self, findings: list[Finding]) -> str:
        return render_csv(findings)


__all__ = [
    "CsvReporter",
    "render_csv",
]
