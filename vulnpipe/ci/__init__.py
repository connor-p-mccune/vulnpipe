"""CI integration: baseline management, diffing, the failure gate, and JUnit output.

The CI stage runs after reporting: it compares the current findings against a saved
:class:`~vulnpipe.ci.baseline.Baseline` (new / persisting / resolved via
:func:`~vulnpipe.ci.differ.diff_findings`), decides a pass/fail verdict from a
severity policy (:func:`~vulnpipe.ci.gate.evaluate_gate`), and can render that
verdict as JUnit XML (:func:`~vulnpipe.ci.junit.build_junit_xml`) alongside the
SARIF report for code-scanning upload. Baseline build/diff/gate are pure; only the
baseline load/save helpers touch the filesystem.
"""

from vulnpipe.ci.baseline import (
    BASELINE_SCHEMA_VERSION,
    Baseline,
    BaselineEntry,
    BaselineError,
    baseline_to_json,
    build_baseline,
    load_baseline,
    merge_baseline,
    save_baseline,
)
from vulnpipe.ci.differ import Diff, diff_findings, diff_to_payload
from vulnpipe.ci.gate import (
    DEFAULT_GATE_SEVERITY,
    GateResult,
    evaluate_gate,
    meets_threshold,
)
from vulnpipe.ci.junit import GateVerdict, build_junit_xml
from vulnpipe.ci.policy import (
    GatePolicy,
    PolicyError,
    PolicyResult,
    PolicyViolation,
    evaluate_policy,
    load_policy,
    policy_from_threshold,
    policy_result_to_payload,
)
from vulnpipe.ci.trends import (
    ScanPoint,
    Trend,
    build_trend,
    render_trend_text,
    trend_to_payload,
)

__all__ = [
    "BASELINE_SCHEMA_VERSION",
    "DEFAULT_GATE_SEVERITY",
    "Baseline",
    "BaselineEntry",
    "BaselineError",
    "Diff",
    "GatePolicy",
    "GateResult",
    "GateVerdict",
    "PolicyError",
    "PolicyResult",
    "PolicyViolation",
    "ScanPoint",
    "Trend",
    "baseline_to_json",
    "build_baseline",
    "build_junit_xml",
    "build_trend",
    "diff_findings",
    "diff_to_payload",
    "evaluate_gate",
    "evaluate_policy",
    "load_baseline",
    "load_policy",
    "meets_threshold",
    "merge_baseline",
    "policy_from_threshold",
    "policy_result_to_payload",
    "render_trend_text",
    "save_baseline",
    "trend_to_payload",
]
