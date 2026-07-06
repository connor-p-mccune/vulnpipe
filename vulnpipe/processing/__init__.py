"""Pure finding transforms: normalize, dedup, false-positive filter, prioritize.

These stages run in order on the findings the scanners produce: normalize cleans
and constructs findings, :func:`deduplicate` collapses repeats, then
:func:`filter_false_positives` drops vetted noise, and :func:`prioritize` orders
what remains. Every transform is pure (findings in -> findings out) so it is
trivially testable; the lone side effect is :func:`load_false_positive_config`,
kept beside the filter it configures.
"""

from vulnpipe.processing.deduplicator import deduplicate, merge_findings
from vulnpipe.processing.false_positive import (
    FalsePositiveConfig,
    FingerprintRule,
    HostRule,
    PluginRule,
    expired_entries,
    filter_false_positives,
    is_false_positive,
    load_false_positive_config,
)
from vulnpipe.processing.normalizer import make_finding
from vulnpipe.processing.ownership import annotate_ownership
from vulnpipe.processing.prioritizer import CriticalityResolver, prioritize

__all__ = [
    "CriticalityResolver",
    "FalsePositiveConfig",
    "FingerprintRule",
    "HostRule",
    "PluginRule",
    "annotate_ownership",
    "deduplicate",
    "expired_entries",
    "filter_false_positives",
    "is_false_positive",
    "load_false_positive_config",
    "make_finding",
    "merge_findings",
    "prioritize",
]
