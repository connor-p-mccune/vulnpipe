"""Suppress known false positives via an allowlist file and a confidence floor.

Scanners are noisy. This stage drops findings an operator has vetted as benign --
matched by stable fingerprint, by scanner plugin/alert id (optionally pinned to a
host), or by host -- and findings whose detection confidence falls below a
configured minimum. The allowlist is loaded from a YAML file (see
``configs/false_positives.example.yaml``).

Suppressions are **risk acceptances**, so every entry supports an optional
``reason`` (why it is accepted -- kept for the audit trail) and an optional
``expires`` date (the last day the acceptance holds). An expired entry stops
suppressing -- the finding resurfaces in reports and the gate -- and
:func:`expired_entries` names it so the caller can warn: acceptances are
revisited, never silently permanent. Bare-string entries (just a fingerprint or
host) remain valid and accept indefinitely.

The filtering itself (:func:`is_false_positive`, :func:`filter_false_positives`) is
a pure function of a finding, a parsed allowlist, and an evaluation date; only
:func:`load_false_positive_config` touches the filesystem. An allowlist with no
``expires`` dates is date-independent; when expiry is in play, callers (and tests)
pass ``today`` explicitly to pin the evaluation. Findings without a confidence
(e.g. Nmap findings, which carry no ZAP-style confidence) are never dropped by the
threshold -- the absence of a confidence signal is not the same as low confidence.
"""

from collections.abc import Iterable
from datetime import date
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, field_validator

from vulnpipe.core.models import Confidence, Finding


class _AcceptanceRule(BaseModel):
    """Fields shared by every allowlist entry: an optional reason and expiry.

    ``expires`` is inclusive -- the entry still suppresses *on* that date and stops
    the day after, matching how "accepted until <date>" is read by humans.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    reason: str | None = None
    expires: date | None = None

    def is_active(self, today: date) -> bool:
        """Whether this entry still suppresses on ``today``."""
        return self.expires is None or today <= self.expires


class FingerprintRule(_AcceptanceRule):
    """Suppress one specific finding by its stable fingerprint (most precise)."""

    fingerprint: str

    def describe(self) -> str:
        """A short human-readable label for logs."""
        return f"fingerprint {self.fingerprint[:12]}..."


class PluginRule(_AcceptanceRule):
    """Suppress a scanner plugin/alert id, optionally only on a specific host."""

    id: str
    host: str | None = None

    def describe(self) -> str:
        """A short human-readable label for logs."""
        return f"plugin {self.id}" if self.host is None else f"plugin {self.id} on {self.host}"


class HostRule(_AcceptanceRule):
    """Suppress every finding on a host (use sparingly)."""

    host: str

    def describe(self) -> str:
        """A short human-readable label for logs."""
        return f"host {self.host}"


class FalsePositiveConfig(BaseModel):
    """A parsed false-positive allowlist (see ``configs/false_positives.example.yaml``).

    An all-default instance suppresses nothing: no fingerprints, plugins, or hosts
    are listed and ``min_confidence`` is unset (no confidence floor). Fingerprint
    and host entries accept either a bare string (accept indefinitely) or a mapping
    with ``reason`` / ``expires`` (a documented, time-boxed acceptance).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    min_confidence: Confidence | None = None
    fingerprints: tuple[FingerprintRule, ...] = ()
    plugins: tuple[PluginRule, ...] = ()
    hosts: tuple[HostRule, ...] = ()

    @field_validator("fingerprints", mode="before")
    @classmethod
    def _coerce_fingerprints(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return [{"fingerprint": item} if isinstance(item, str) else item for item in value]
        return value

    @field_validator("hosts", mode="before")
    @classmethod
    def _coerce_hosts(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return [{"host": item} if isinstance(item, str) else item for item in value]
        return value


def load_false_positive_config(path: str | Path) -> FalsePositiveConfig:
    """Load and validate a false-positive allowlist YAML file.

    An empty file yields an empty allowlist. Raises :class:`FileNotFoundError` if
    ``path`` does not exist and :class:`pydantic.ValidationError` if the contents do
    not match the schema.
    """
    config_path = Path(path)
    if not config_path.is_file():
        raise FileNotFoundError(f"False-positive allowlist not found: {config_path}")
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError(f"Allowlist root must be a mapping, got {type(raw).__name__}")
    return FalsePositiveConfig.model_validate(raw)


def is_false_positive(
    finding: Finding, allowlist: FalsePositiveConfig, *, today: date | None = None
) -> bool:
    """Whether ``finding`` is suppressed by ``allowlist`` on ``today``.

    Suppressed if an *active* (unexpired) entry matches -- its fingerprint is
    allowlisted, its host is allowlisted, or a plugin rule matches its plugin id
    (and host, when the rule pins one) -- or it carries a confidence below
    ``min_confidence`` (the confidence floor never expires; it is a quality bar,
    not an acceptance). ``today`` defaults to the current date; pass it explicitly
    for a pinned, reproducible evaluation.
    """
    moment = today if today is not None else date.today()
    for fp_rule in allowlist.fingerprints:
        if fp_rule.fingerprint == finding.fingerprint and fp_rule.is_active(moment):
            return True
    for host_rule in allowlist.hosts:
        if host_rule.host == finding.host and host_rule.is_active(moment):
            return True
    for plugin_rule in allowlist.plugins:
        if (
            finding.plugin_id is not None
            and finding.plugin_id == plugin_rule.id
            and (plugin_rule.host is None or plugin_rule.host == finding.host)
            and plugin_rule.is_active(moment)
        ):
            return True
    floor = allowlist.min_confidence
    return (
        floor is not None
        and finding.confidence is not None
        and finding.confidence.rank < floor.rank
    )


def filter_false_positives(
    findings: Iterable[Finding], allowlist: FalsePositiveConfig, *, today: date | None = None
) -> list[Finding]:
    """Return only the findings ``allowlist`` does not suppress (order preserved)."""
    moment = today if today is not None else date.today()
    return [
        finding for finding in findings if not is_false_positive(finding, allowlist, today=moment)
    ]


def expired_entries(
    allowlist: FalsePositiveConfig, *, today: date | None = None
) -> tuple[str, ...]:
    """Human-readable labels for entries whose acceptance window has lapsed.

    These entries no longer suppress anything; callers surface them as warnings so
    an expired risk acceptance triggers a review rather than vanishing silently.
    Entries without an ``expires`` date are never listed.
    """
    moment = today if today is not None else date.today()
    labels: list[str] = []
    rules: tuple[FingerprintRule | PluginRule | HostRule, ...] = (
        *allowlist.fingerprints,
        *allowlist.plugins,
        *allowlist.hosts,
    )
    for rule in rules:
        if rule.expires is not None and not rule.is_active(moment):
            label = f"{rule.describe()} (expired {rule.expires.isoformat()}"
            if rule.reason:
                label += f"; reason: {rule.reason}"
            labels.append(label + ")")
    return tuple(labels)


__all__ = [
    "FalsePositiveConfig",
    "FingerprintRule",
    "HostRule",
    "PluginRule",
    "expired_entries",
    "filter_false_positives",
    "is_false_positive",
    "load_false_positive_config",
]
