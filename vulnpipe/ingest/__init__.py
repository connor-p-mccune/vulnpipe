"""Ingest third-party scanner output into the shared :class:`Finding` model.

vulnpipe's thesis is that one normalized model lets every downstream stage --
enrichment, dedup, prioritization, reporting, diffing, gating, SLAs -- work
regardless of which tool produced a finding. This package extends that to scanners
vulnpipe does not drive itself: point it at a JSON report from
`Trivy <https://trivy.dev>`_ or `Grype <https://github.com/anchore/grype>`_ (the two
dominant open-source container / SBOM scanners) and it normalizes their findings
into the same model the ``convert`` CLI command then renders, gates, or merges like
any other findings JSON.

Like the SBOM layer this is **passive**: it reads a local file and maps it, never
probing anything, so it needs no scope or authorization. Each importer is a pure
``dict -> list[Finding]`` function routed by name through a small registry; a
malformed document raises :class:`IngestError` rather than producing partial garbage.
"""

from collections.abc import Callable

from vulnpipe.core.models import Finding, Severity


class IngestError(Exception):
    """Raised when a third-party report cannot be parsed into findings."""


#: Case-insensitive scanner severity label -> normalized :class:`Severity`.
_SEVERITY: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "negligible": Severity.INFORMATIONAL,
    "informational": Severity.INFORMATIONAL,
    "info": Severity.INFORMATIONAL,
    "unknown": Severity.INFORMATIONAL,
    "none": Severity.INFORMATIONAL,
}


def severity_from_label(label: object) -> Severity:
    """Map a scanner's severity label onto a :class:`Severity`.

    Case-insensitive; an unrecognized or missing label degrades to
    :attr:`Severity.INFORMATIONAL` -- never guessed upward.
    """
    if not isinstance(label, str):
        return Severity.INFORMATIONAL
    return _SEVERITY.get(label.strip().lower(), Severity.INFORMATIONAL)


#: A pure importer: a loaded JSON document in, normalized findings out.
Ingester = Callable[[object], list[Finding]]

#: The supported third-party formats (concrete parsers are imported lazily on use,
#: so the package has no import cycle with its parser modules).
_INGESTER_NAMES = ("grype", "trivy")


def available_ingesters() -> list[str]:
    """Return the sorted names of the supported third-party formats."""
    return sorted(_INGESTER_NAMES)


def get_ingester(name: str) -> Ingester:
    """Return the importer for ``name`` (e.g. ``"trivy"`` / ``"grype"``).

    Raises :class:`IngestError` for an unknown format, naming the supported ones.
    """
    if name == "trivy":
        from vulnpipe.ingest.trivy import parse_trivy

        return parse_trivy
    if name == "grype":
        from vulnpipe.ingest.grype import parse_grype

        return parse_grype
    raise IngestError(
        f"Unknown ingest format {name!r}; supported: {', '.join(available_ingesters())}"
    )


__all__ = [
    "IngestError",
    "Ingester",
    "available_ingesters",
    "get_ingester",
    "severity_from_label",
]
