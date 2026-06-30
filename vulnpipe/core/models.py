"""Canonical data models shared across the pipeline.

Every scanner normalizes its output into :class:`Finding` objects; everything
downstream (enrichment, dedup, false-positive filtering, prioritization,
reporting, CI diffing) operates only on this model. A finding carries a stable
:attr:`Finding.fingerprint` used for deduplication and baseline diffing.
"""

import hashlib
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator

_VALID_PROTOCOLS = frozenset({"tcp", "udp", "sctp"})


class Severity(StrEnum):
    """Normalized severity, ordered low-to-high via :attr:`rank`.

    ZAP risk levels map onto the first four values; CVSS-derived findings may
    reach :attr:`CRITICAL` (see :meth:`from_cvss_score`).
    """

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Integer ordering for sorting/comparison (higher is more severe)."""
        return _SEVERITY_ORDER[self]

    @classmethod
    def from_cvss_score(cls, score: float) -> "Severity":
        """Map a CVSS v3 base score to a severity using the FIRST qualitative bands.

        0.0 -> Informational, 0.1-3.9 -> Low, 4.0-6.9 -> Medium,
        7.0-8.9 -> High, 9.0-10.0 -> Critical.
        """
        if score < 0.0 or score > 10.0:
            raise ValueError(f"CVSS score out of range [0, 10]: {score}")
        if score == 0.0:
            return cls.INFORMATIONAL
        if score < 4.0:
            return cls.LOW
        if score < 7.0:
            return cls.MEDIUM
        if score < 9.0:
            return cls.HIGH
        return cls.CRITICAL


_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(StrEnum):
    """Detection confidence carried onto findings (mirrors ZAP's levels).

    The false-positive filter compares :attr:`rank` against a threshold.
    """

    FALSE_POSITIVE = "false_positive"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"

    @property
    def rank(self) -> int:
        """Integer ordering for threshold comparisons (higher is more confident)."""
        return _CONFIDENCE_ORDER[self]


_CONFIDENCE_ORDER: dict[Confidence, int] = {
    Confidence.FALSE_POSITIVE: 0,
    Confidence.LOW: 1,
    Confidence.MEDIUM: 2,
    Confidence.HIGH: 3,
    Confidence.CONFIRMED: 4,
}


class AssetCriticality(StrEnum):
    """Business criticality of a scanned asset, ordered low-to-high via :attr:`rank`.

    Sourced from configuration (``prioritization.assets``) and used as a tie-breaker
    when ranking findings: among otherwise equally severe issues, those on more
    critical assets surface first.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Integer ordering for prioritization (higher is more critical)."""
        return _ASSET_CRITICALITY_ORDER[self]


_ASSET_CRITICALITY_ORDER: dict[AssetCriticality, int] = {
    AssetCriticality.LOW: 0,
    AssetCriticality.MEDIUM: 1,
    AssetCriticality.HIGH: 2,
    AssetCriticality.CRITICAL: 3,
}


def normalize_title(title: str) -> str:
    """Normalize a finding title for stable fingerprinting.

    Collapses internal whitespace, strips ends, and lowercases so that cosmetic
    differences in scanner output do not change the fingerprint.
    """
    return " ".join(title.split()).lower()


def compute_fingerprint(
    *,
    host: str,
    port: int | None,
    source: str,
    plugin_or_alert_id: str | None,
    title: str,
) -> str:
    """Compute the stable finding fingerprint.

    ``sha256(host | port | source | plugin_or_alert_id | normalized_title)``.
    Must be stable across runs for the same underlying issue: this is what the
    deduplicator and the CI differ rely on.
    """
    parts = [
        host,
        "" if port is None else str(port),
        source,
        plugin_or_alert_id or "",
        normalize_title(title),
    ]
    digest = hashlib.sha256("|".join(parts).encode("utf-8"))
    return digest.hexdigest()


class Service(BaseModel):
    """A network service observed on a host port."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    port: int = Field(ge=0, le=65535)
    protocol: str = "tcp"
    name: str | None = None
    product: str | None = None
    version: str | None = None
    state: str = "open"

    @field_validator("protocol")
    @classmethod
    def _normalize_protocol(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in _VALID_PROTOCOLS:
            raise ValueError(f"Unsupported protocol: {value!r}")
        return normalized


class Host(BaseModel):
    """A scanned host with its discovered services and optional OS guess."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    address: str
    hostname: str | None = None
    os: str | None = None
    services: tuple[Service, ...] = ()


class Finding(BaseModel):
    """A single normalized vulnerability/observation from any scanner.

    Immutable (``frozen``): enrichment and processing stages produce new findings
    via :meth:`pydantic.BaseModel.model_copy` rather than mutating in place, which
    keeps the fingerprint stable across the pipeline.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: str = Field(description="Scanner that produced the finding, e.g. 'nmap' or 'zap'.")
    host: str = Field(description="Target host or IP the finding pertains to.")
    title: str = Field(description="Short human-readable title / alert name.")
    severity: Severity = Severity.INFORMATIONAL
    port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None
    plugin_id: str | None = Field(
        default=None, description="NSE script id or ZAP alert/plugin id used in the fingerprint."
    )
    confidence: Confidence | None = None
    description: str | None = None
    solution: str | None = None
    evidence: str | None = None
    references: tuple[str, ...] = ()
    cve_ids: tuple[str, ...] = ()
    cwe_ids: tuple[str, ...] = ()
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: str | None = None
    epss_score: float | None = Field(default=None, ge=0.0, le=1.0)
    epss_percentile: float | None = Field(default=None, ge=0.0, le=1.0)
    kev: bool = Field(
        default=False,
        description=(
            "Whether a cited CVE appears in the CISA Known Exploited Vulnerabilities "
            "(KEV) catalog -- i.e. is being actively exploited in the wild. Set by the "
            "enrichment stage; defaults to False (absence of evidence, not a guess)."
        ),
    )
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("protocol")
    @classmethod
    def _normalize_protocol(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        if normalized not in _VALID_PROTOCOLS:
            raise ValueError(f"Unsupported protocol: {value!r}")
        return normalized

    @computed_field  # type: ignore[prop-decorator]
    @property
    def fingerprint(self) -> str:
        """Stable identity of this finding; see :func:`compute_fingerprint`."""
        return compute_fingerprint(
            host=self.host,
            port=self.port,
            source=self.source,
            plugin_or_alert_id=self.plugin_id,
            title=self.title,
        )


__all__ = [
    "AssetCriticality",
    "Confidence",
    "Finding",
    "Host",
    "Service",
    "Severity",
    "compute_fingerprint",
    "normalize_title",
]
