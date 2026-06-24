"""Suppress known false positives via an allowlist file and a confidence floor.

Scanners are noisy. This stage drops findings an operator has vetted as benign --
matched by stable fingerprint, by scanner plugin/alert id (optionally pinned to a
host), or by host -- and findings whose detection confidence falls below a
configured minimum. The allowlist is loaded from a YAML file (see
``configs/false_positives.example.yaml``).

The filtering itself (:func:`is_false_positive`, :func:`filter_false_positives`) is
a pure function of a finding and a parsed allowlist; only :func:`load_false_positive_config`
touches the filesystem. Findings without a confidence (e.g. Nmap findings, which
carry no ZAP-style confidence) are never dropped by the threshold -- the absence of
a confidence signal is not the same as low confidence.
"""

from collections.abc import Iterable
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict

from vulnpipe.core.models import Confidence, Finding


class PluginRule(BaseModel):
    """Suppress a scanner plugin/alert id, optionally only on a specific host."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    host: str | None = None


class FalsePositiveConfig(BaseModel):
    """A parsed false-positive allowlist (see ``configs/false_positives.example.yaml``).

    An all-default instance suppresses nothing: no fingerprints, plugins, or hosts
    are listed and ``min_confidence`` is unset (no confidence floor).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    min_confidence: Confidence | None = None
    fingerprints: tuple[str, ...] = ()
    plugins: tuple[PluginRule, ...] = ()
    hosts: tuple[str, ...] = ()


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


def is_false_positive(finding: Finding, allowlist: FalsePositiveConfig) -> bool:
    """Whether ``finding`` is suppressed by ``allowlist``.

    Suppressed if its fingerprint is allowlisted, its host is allowlisted, a plugin
    rule matches its plugin id (and host, when the rule pins one), or it carries a
    confidence below ``min_confidence``.
    """
    if finding.fingerprint in allowlist.fingerprints:
        return True
    if finding.host in allowlist.hosts:
        return True
    for rule in allowlist.plugins:
        if (
            finding.plugin_id is not None
            and finding.plugin_id == rule.id
            and (rule.host is None or rule.host == finding.host)
        ):
            return True
    floor = allowlist.min_confidence
    return (
        floor is not None
        and finding.confidence is not None
        and finding.confidence.rank < floor.rank
    )


def filter_false_positives(
    findings: Iterable[Finding], allowlist: FalsePositiveConfig
) -> list[Finding]:
    """Return only the findings ``allowlist`` does not suppress (order preserved)."""
    return [finding for finding in findings if not is_false_positive(finding, allowlist)]


__all__ = [
    "FalsePositiveConfig",
    "PluginRule",
    "filter_false_positives",
    "is_false_positive",
    "load_false_positive_config",
]
