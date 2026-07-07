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
from vulnpipe.processing.ownership import annotate_ownership, finding_owner, finding_tags
from vulnpipe.processing.prioritizer import CriticalityResolver, prioritize
from vulnpipe.processing.query import FindingQuery, apply_query, build_query, matches

__all__ = [
    "CriticalityResolver",
    "FalsePositiveConfig",
    "FindingQuery",
    "FingerprintRule",
    "HostRule",
    "PluginRule",
    "annotate_ownership",
    "apply_query",
    "build_query",
    "deduplicate",
    "expired_entries",
    "filter_false_positives",
    "finding_owner",
    "finding_tags",
    "is_false_positive",
    "load_false_positive_config",
    "make_finding",
    "matches",
    "merge_findings",
    "prioritize",
]
