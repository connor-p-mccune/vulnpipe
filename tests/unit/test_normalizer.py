"""Unit tests for the shared finding-normalization helpers."""

import pytest

from vulnpipe.processing.normalizer import (
    clean_cves,
    clean_text,
    clean_tuple,
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
