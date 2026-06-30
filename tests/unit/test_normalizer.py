"""Unit tests for the shared finding-normalization helpers."""

import pytest

from vulnpipe.core.models import Confidence, Severity
from vulnpipe.processing.normalizer import (
    clean_cves,
    clean_text,
    clean_tuple,
    make_finding,
    normalize_cve,
    parse_cvss,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("  hello  ", "hello"),
        ("line one\nline two", "line one\nline two"),  # internal whitespace preserved
        ("   ", None),
        ("", None),
        (None, None),
    ],
)
def test_clean_text(value: str | None, expected: str | None) -> None:
    assert clean_text(value) == expected


def test_clean_tuple_dedupes_and_orders() -> None:
    assert clean_tuple(["b", " a ", "b", "a", "", None, "c"]) == ("b", "a", "c")


def test_clean_tuple_empty() -> None:
    assert clean_tuple([]) == ()
    assert clean_tuple([None, "  ", ""]) == ()


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("CVE-2019-16905", "CVE-2019-16905"),
        ("  cve-2017-15906 ", "CVE-2017-15906"),
        ("CVE-2021-1234567", "CVE-2021-1234567"),  # 7-digit sequence
        ("CVE-2019-169", None),  # too few digits
        ("not-a-cve", None),
        ("prefix CVE-2019-16905", None),  # must be a full match, not substring
        (None, None),
    ],
)
def test_normalize_cve(value: str | None, expected: str | None) -> None:
    assert normalize_cve(value) == expected


def test_clean_cves_filters_and_dedupes() -> None:
    raw = ["CVE-2019-16905", "cve-2019-16905", "garbage", "CVE-2017-15906", None]
    assert clean_cves(raw) == ("CVE-2019-16905", "CVE-2017-15906")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (7.8, 7.8),
        ("5.3", 5.3),
        (0, 0.0),
        (10, 10.0),
        ("0.0", 0.0),
        (-1.0, None),  # below range
        (10.1, None),  # above range
        ("not-a-number", None),
        (None, None),
        (True, None),  # bools are not scores
        (float("nan"), None),
    ],
)
def test_parse_cvss(value: float | int | str | None, expected: float | None) -> None:
    assert parse_cvss(value) == expected


def test_make_finding_derives_severity_from_cvss() -> None:
    finding = make_finding(source="nmap", host="10.0.0.5", title="CVE-2019-16905", cvss_score="7.8")
    assert finding.severity is Severity.HIGH
    assert finding.cvss_score == 7.8


def test_make_finding_defaults_severity_informational_without_cvss() -> None:
    # No CVSS and no explicit severity -> unknown, never guessed.
    finding = make_finding(source="nmap", host="10.0.0.5", title="Open port 22/tcp")
    assert finding.severity is Severity.INFORMATIONAL
    assert finding.cvss_score is None


def test_make_finding_respects_explicit_severity() -> None:
    finding = make_finding(
        source="zap",
        host="app.example.com",
        title="Reflected XSS",
        severity=Severity.MEDIUM,
        cvss_score="9.0",  # explicit severity wins over the derived one
    )
    assert finding.severity is Severity.MEDIUM


def test_make_finding_cleans_fields() -> None:
    finding = make_finding(
        source="nmap",
        host="10.0.0.5",
        title="  Open   port   22/tcp  ",
        plugin_id="  vulners  ",
        description="  see details  ",
        references=["https://a", "https://a", " ", None],
        cve_ids=["cve-2019-16905", "garbage", "CVE-2019-16905"],
        cwe_ids=["79", "79"],
        confidence=Confidence.MEDIUM,
    )
    assert finding.title == "Open port 22/tcp"  # collapsed
    assert finding.plugin_id == "vulners"
    assert finding.description == "see details"
    assert finding.references == ("https://a",)
    assert finding.cve_ids == ("CVE-2019-16905",)
    assert finding.cwe_ids == ("79",)
    assert finding.confidence is Confidence.MEDIUM


def test_make_finding_rejects_empty_title() -> None:
    with pytest.raises(ValueError, match="title must be non-empty"):
        make_finding(source="nmap", host="10.0.0.5", title="   ")


def test_make_finding_out_of_range_cvss_becomes_unknown() -> None:
    finding = make_finding(source="nmap", host="10.0.0.5", title="CVE-2019-16905", cvss_score="99")
    assert finding.cvss_score is None
    assert finding.severity is Severity.INFORMATIONAL


def test_make_finding_fingerprint_is_stable() -> None:
    kwargs = {"source": "nmap", "host": "10.0.0.5", "title": "Open port 22/tcp", "port": 22}
    first = make_finding(**kwargs)  # type: ignore[arg-type]
    second = make_finding(**kwargs)  # type: ignore[arg-type]
    assert first.fingerprint == second.fingerprint
    # Title whitespace differences must not change the fingerprint.
    spaced = make_finding(source="nmap", host="10.0.0.5", title="Open   port 22/tcp", port=22)
    assert spaced.fingerprint == first.fingerprint


def test_make_finding_metadata_defaults_to_empty_dict() -> None:
    assert make_finding(source="nmap", host="10.0.0.5", title="x").metadata == {}


def test_make_finding_kev_defaults_false_and_passes_through() -> None:
    assert make_finding(source="nmap", host="10.0.0.5", title="x").kev is False
    flagged = make_finding(source="nmap", host="10.0.0.5", title="CVE-2021-44228", kev=True)
    assert flagged.kev is True
