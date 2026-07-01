"""JSON report renderer -- the canonical pipeline artifact.

Serializes findings (including their stable fingerprint) into deterministic JSON.
This is the format the pipeline writes to disk, the HTML/SARIF renderers and the
CI differ read back, and tooling consumes, so it is intentionally lossless and
round-trippable: :func:`build_report` -> JSON -> :func:`report_to_findings`
reproduces the original findings exactly.

Determinism: findings are emitted in the order given (the prioritized order), each
finding keeps the model's fixed field order, and the summary lists every severity
band in a fixed order. No wall-clock timestamp is embedded, so the same findings
always render byte-for-byte identically.
"""

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from vulnpipe import __version__
from vulnpipe.core.models import Finding
from vulnpipe.reporting.base import BaseReporter
from vulnpipe.reporting.summary import SEVERITY_DISPLAY_ORDER, summarize

#: Version of the vulnpipe JSON report envelope (distinct from the tool version).
REPORT_SCHEMA_VERSION = "1.0"

#: Model fields that are computed/output-only and must be dropped before a finding
#: dict is validated back into a :class:`Finding` (``extra="forbid"`` rejects them).
_COMPUTED_FIELDS = frozenset({"fingerprint", "risk_score"})


def build_report(findings: Iterable[Finding]) -> dict[str, Any]:
    """Build the structured JSON report payload for ``findings``.

    The envelope carries the schema version, the tool identity, a severity/host
    summary, and the full findings list (each finding serialized with its
    fingerprint). The findings keep their incoming order.
    """
    items = list(findings)
    summary = summarize(items)
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "tool": {"name": "vulnpipe", "version": __version__},
        "summary": {
            "total": summary.total,
            "hosts": summary.host_count,
            "by_severity": {
                severity.value: summary.by_severity[severity] for severity in SEVERITY_DISPLAY_ORDER
            },
        },
        "findings": [finding.model_dump(mode="json") for finding in items],
    }


def report_to_findings(payload: dict[str, Any]) -> list[Finding]:
    """Reconstruct findings from a JSON report payload produced by :func:`build_report`.

    Computed fields (the fingerprint) are stripped before validation since they are
    not constructor inputs; the fingerprint is recomputed from the identity fields
    and is therefore identical to the original.
    """
    raw_findings = payload.get("findings", [])
    if not isinstance(raw_findings, list):
        raise ValueError("Report payload 'findings' must be a list")
    findings: list[Finding] = []
    for raw in raw_findings:
        if not isinstance(raw, dict):
            raise ValueError("Each finding in the report must be a mapping")
        data = {key: value for key, value in raw.items() if key not in _COMPUTED_FIELDS}
        findings.append(Finding.model_validate(data))
    return findings


def load_findings(path: str | Path) -> list[Finding]:
    """Load findings from a JSON report file on disk.

    Accepts either a full report envelope (a mapping with a ``findings`` list) or a
    bare list of finding objects, so the ``report`` and ``diff`` commands can read
    whatever JSON they are pointed at.
    """
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, list):
        payload = {"findings": payload}
    if not isinstance(payload, dict):
        raise ValueError("Report JSON must be an object or a list of findings")
    return report_to_findings(payload)


class JsonReporter(BaseReporter):
    """Render findings into the canonical, deterministic JSON report string."""

    name = "json"

    def render(self, findings: list[Finding]) -> str:
        report = build_report(findings)
        return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


__all__ = [
    "REPORT_SCHEMA_VERSION",
    "JsonReporter",
    "build_report",
    "load_findings",
    "report_to_findings",
]
