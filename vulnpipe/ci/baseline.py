"""Baseline persistence: the accepted set of findings to diff future runs against.

A baseline records the findings an operator has reviewed and accepted, keyed by
their stable :attr:`~vulnpipe.core.models.Finding.fingerprint`. Storing the
fingerprint plus a small metadata snapshot (source, host, port, title, severity)
is enough for the differ to recognize a finding across runs *and* to describe a
finding that has since been **resolved** (one present in the baseline but gone
from the current scan), without keeping a full second copy of every field.

The split mirrors the rest of the codebase: :func:`build_baseline` /
:func:`merge_baseline` are pure (findings in, a :class:`Baseline` out) and only
:func:`save_baseline` / :func:`load_baseline` touch the filesystem. The on-disk
form is deterministic -- entries are written in fingerprint order and no
wall-clock timestamp is embedded -- so the same findings always serialize
byte-for-byte identically and ``save`` -> ``load`` round-trips exactly.
"""

import json
from collections.abc import Iterable
from datetime import date
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from vulnpipe.core.models import Finding, Severity

#: Version of the baseline file envelope (distinct from the tool version).
BASELINE_SCHEMA_VERSION = "1.0"


class BaselineError(Exception):
    """Raised when a baseline file cannot be read or fails schema validation."""


class BaselineEntry(BaseModel):
    """One accepted finding recorded in a baseline: identity plus display metadata.

    Carries the finding's fingerprint (its stable identity, used by the differ)
    together with the few fields needed to describe it in a report when it later
    resolves. It is intentionally a snapshot, not the whole finding.

    ``first_seen`` is an optional record of the date the finding first entered the
    baseline; it powers age / SLA reporting (:mod:`vulnpipe.ci.sla`) and is omitted
    from the on-disk form when unset, so an age-untracked baseline is byte-identical
    to one written before the field existed.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    fingerprint: str
    source: str
    host: str
    title: str
    severity: Severity = Severity.INFORMATIONAL
    port: int | None = None
    first_seen: date | None = None

    @classmethod
    def from_finding(cls, finding: Finding, *, first_seen: date | None = None) -> "BaselineEntry":
        """Snapshot the identity and display fields of ``finding`` into an entry."""
        return cls(
            fingerprint=finding.fingerprint,
            source=finding.source,
            host=finding.host,
            title=finding.title,
            severity=finding.severity,
            port=finding.port,
            first_seen=first_seen,
        )


class Baseline(BaseModel):
    """An accepted set of findings, keyed by fingerprint, to diff future runs against."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = BASELINE_SCHEMA_VERSION
    entries: tuple[BaselineEntry, ...] = ()

    @property
    def fingerprints(self) -> frozenset[str]:
        """The set of fingerprints recorded in this baseline."""
        return frozenset(entry.fingerprint for entry in self.entries)

    def entry_for(self, fingerprint: str) -> BaselineEntry | None:
        """Return the entry with ``fingerprint``, or ``None`` if it is not recorded."""
        for entry in self.entries:
            if entry.fingerprint == fingerprint:
                return entry
        return None

    def first_seen(self, fingerprint: str) -> date | None:
        """Return the recorded first-seen date for ``fingerprint``, or ``None``."""
        entry = self.entry_for(fingerprint)
        return entry.first_seen if entry is not None else None


def _entries_from_findings(
    findings: Iterable[Finding], *, first_seen: date | None = None
) -> dict[str, BaselineEntry]:
    """Map fingerprint -> entry for ``findings``, keeping the first sighting of each."""
    entries: dict[str, BaselineEntry] = {}
    for finding in findings:
        entries.setdefault(
            finding.fingerprint, BaselineEntry.from_finding(finding, first_seen=first_seen)
        )
    return entries


def _ordered(entries: dict[str, BaselineEntry]) -> tuple[BaselineEntry, ...]:
    """Order entries by fingerprint so the stored baseline is canonical and stable."""
    return tuple(entries[key] for key in sorted(entries))


def build_baseline(findings: Iterable[Finding], *, first_seen: date | None = None) -> Baseline:
    """Build a baseline from ``findings`` (deduplicated by fingerprint).

    The result is order-independent: entries are stored in fingerprint order, so
    the same set of findings always produces an identical baseline regardless of
    how they were ordered on input. When ``first_seen`` is given, every entry is
    stamped with it (for age / SLA tracking); omitted, entries carry no date and the
    output is byte-identical to an age-untracked baseline.
    """
    return Baseline(entries=_ordered(_entries_from_findings(findings, first_seen=first_seen)))


def merge_baseline(
    baseline: Baseline, findings: Iterable[Finding], *, first_seen: date | None = None
) -> Baseline:
    """Return ``baseline`` extended with any new findings (union by fingerprint).

    Existing entries are preserved unchanged -- a finding whose fingerprint is already
    recorded keeps its stored snapshot *and* its original ``first_seen``, so an issue's
    age is measured from when it truly first appeared. Only genuinely new entries take
    the supplied ``first_seen``. Used to accept newly introduced findings into an
    existing baseline.
    """
    merged = {entry.fingerprint: entry for entry in baseline.entries}
    for fingerprint, entry in _entries_from_findings(findings, first_seen=first_seen).items():
        merged.setdefault(fingerprint, entry)
    return Baseline(schema_version=baseline.schema_version, entries=_ordered(merged))


def baseline_to_json(baseline: Baseline) -> str:
    """Serialize ``baseline`` to deterministic JSON (no timestamp; stable order).

    An entry with no ``first_seen`` omits the key entirely, so an age-untracked
    baseline serializes exactly as it did before the field existed.
    """
    payload: dict[str, Any] = baseline.model_dump(mode="json")
    for entry in payload.get("entries", []):
        if isinstance(entry, dict) and entry.get("first_seen") is None:
            entry.pop("first_seen", None)
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def save_baseline(baseline: Baseline, path: str | Path) -> None:
    """Write ``baseline`` to ``path`` as deterministic JSON, creating parent dirs."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(baseline_to_json(baseline), encoding="utf-8")


def load_baseline(path: str | Path) -> Baseline:
    """Load and validate a baseline JSON file written by :func:`save_baseline`.

    Raises :class:`BaselineError` if the file is missing, is not valid JSON, or does
    not match the baseline schema.
    """
    source = Path(path)
    if not source.is_file():
        raise BaselineError(f"Baseline file not found: {source}")
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BaselineError(f"Failed to read baseline {source}: {exc}") from exc
    if not isinstance(raw, dict):
        raise BaselineError(f"Baseline root must be a mapping, got {type(raw).__name__}")
    try:
        return Baseline.model_validate(raw)
    except ValidationError as exc:
        raise BaselineError(f"Invalid baseline in {source}:\n{exc}") from exc


__all__ = [
    "BASELINE_SCHEMA_VERSION",
    "Baseline",
    "BaselineEntry",
    "BaselineError",
    "baseline_to_json",
    "build_baseline",
    "load_baseline",
    "merge_baseline",
    "save_baseline",
]
