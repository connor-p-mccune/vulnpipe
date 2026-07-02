"""CycloneDX SBOM parsing: a component inventory in, typed components out.

A software bill of materials (SBOM) declares what a piece of software is made of.
This module parses the CycloneDX JSON form (the format emitted by ``syft``,
``cdxgen``, ``pip-audit --format cyclonedx-json``, and most build tooling) into a
small typed model the analyzer can query against a vulnerability database. Parsing
is pure -- a JSON mapping in, an :class:`Sbom` out -- so it is unit-testable from a
fixture document; only :func:`load_sbom` touches the filesystem.

The parser is deliberately honest and lenient in the usual vulnpipe way: component
entries that are malformed (no name) are skipped rather than coerced, duplicates
are dropped keeping the first occurrence, and a document that declares a
``bomFormat`` other than CycloneDX is rejected outright rather than half-read.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class SbomError(Exception):
    """Raised when an SBOM document cannot be loaded or is not CycloneDX."""


@dataclass(frozen=True)
class Component:
    """One declared component: the unit the analyzer queries advisories for."""

    name: str
    version: str | None = None
    purl: str | None = None

    @property
    def ecosystem(self) -> str | None:
        """The package ecosystem from the purl type (``pkg:pypi/...`` -> ``pypi``)."""
        if self.purl is None or not self.purl.startswith("pkg:"):
            return None
        remainder = self.purl[len("pkg:") :]
        ecosystem = remainder.split("/", 1)[0]
        return ecosystem or None

    @property
    def label(self) -> str:
        """A compact ``name version`` display label."""
        return self.name if self.version is None else f"{self.name} {self.version}"


@dataclass(frozen=True)
class Sbom:
    """A parsed SBOM: the subject (what the SBOM describes) and its components."""

    subject: str
    components: tuple[Component, ...]


def _clean(value: Any) -> str | None:
    """Return a stripped non-empty string, or ``None``."""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _parse_component(item: Any) -> Component | None:
    """Parse one ``components[]`` entry, or ``None`` when it has no usable name."""
    if not isinstance(item, Mapping):
        return None
    name = _clean(item.get("name"))
    if name is None:
        return None
    return Component(
        name=name,
        version=_clean(item.get("version")),
        purl=_clean(item.get("purl")),
    )


def _subject(payload: Mapping[str, Any], default: str) -> str:
    """The SBOM's subject: ``metadata.component.name`` when declared, else ``default``.

    Deliberately excludes the subject's *version* so a finding's identity (and the
    CI baseline built on it) stays stable across releases of the application the
    SBOM describes.
    """
    metadata = payload.get("metadata")
    if isinstance(metadata, Mapping):
        component = metadata.get("component")
        if isinstance(component, Mapping):
            name = _clean(component.get("name"))
            if name is not None:
                return name
    return default


def parse_cyclonedx(payload: Mapping[str, Any], *, default_subject: str = "sbom") -> Sbom:
    """Parse a CycloneDX JSON document into an :class:`Sbom`.

    Raises :class:`SbomError` when the document declares a non-CycloneDX
    ``bomFormat``. Malformed component entries are skipped; duplicates (same purl,
    or same name+version when there is no purl) keep their first occurrence.
    """
    declared = payload.get("bomFormat")
    if declared is not None and declared != "CycloneDX":
        raise SbomError(f"Unsupported SBOM format: {declared!r} (expected CycloneDX)")

    raw_components = payload.get("components")
    components: list[Component] = []
    seen: set[str] = set()
    if isinstance(raw_components, list):
        for item in raw_components:
            component = _parse_component(item)
            if component is None:
                continue
            key = component.purl or f"{component.name}@{component.version or ''}"
            if key in seen:
                continue
            seen.add(key)
            components.append(component)
    return Sbom(subject=_subject(payload, default_subject), components=tuple(components))


def load_sbom(path: str | Path) -> Sbom:
    """Load a CycloneDX JSON SBOM from disk.

    The file stem is the fallback subject when the document does not declare
    ``metadata.component``. Raises :class:`SbomError` for a missing file, invalid
    JSON, or a non-mapping root.
    """
    sbom_path = Path(path)
    if not sbom_path.is_file():
        raise SbomError(f"SBOM file not found: {sbom_path}")
    try:
        payload = json.loads(sbom_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SbomError(f"Failed to read SBOM {sbom_path}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise SbomError(f"SBOM root must be a JSON object, got {type(payload).__name__}")
    return parse_cyclonedx(payload, default_subject=sbom_path.stem)


__all__ = [
    "Component",
    "Sbom",
    "SbomError",
    "load_sbom",
    "parse_cyclonedx",
]
