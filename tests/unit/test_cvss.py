"""Unit tests for CVSS vector parsing and scoring (no network)."""

from dataclasses import FrozenInstanceError

import pytest

from vulnpipe.core.models import Severity
from vulnpipe.enrichment.cvss import CvssResult, parse_vector


def test_parse_v31_vector() -> None:
    result = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert result is not None
    assert result.score == 9.8
    assert result.version == "3.1"
    assert result.severity is Severity.CRITICAL
    assert result.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_parse_v30_vector() -> None:
    result = parse_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N")
    assert result is not None
    assert result.version == "3.0"
    assert result.score == 5.4
    assert result.severity is Severity.MEDIUM


def test_parse_v40_vector() -> None:
    result = parse_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
    assert result is not None
    assert result.version == "4.0"
    assert result.score == 9.3
    assert result.severity is Severity.CRITICAL


def test_parse_v2_vector_has_no_prefix() -> None:
    result = parse_vector("AV:N/AC:L/Au:N/C:C/I:C/A:C")
    assert result is not None
    assert result.version == "2.0"
    assert result.score == 10.0
    assert result.severity is Severity.CRITICAL


def test_parse_normalizes_whitespace_and_keeps_score_consistent() -> None:
    # The returned score is re-derived from the vector, not echoed from input.
    result = parse_vector("  CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N  ")
    assert result is not None
    assert 0.0 <= result.score <= 10.0
    assert result.severity is Severity.from_cvss_score(result.score)


@pytest.mark.parametrize(
    "vector",
    [
        None,
        "",
        "   ",
        "not-a-vector",
        "CVSS:3.1/garbage",
        "CVSS:9.9/AV:N",  # unsupported version prefix -> unknown, not guessed
        "CVSS:1.0/AV:N",
    ],
)
def test_parse_bad_input_returns_none(vector: str | None) -> None:
    assert parse_vector(vector) is None


def test_result_is_frozen() -> None:
    result = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert isinstance(result, CvssResult)
    with pytest.raises(FrozenInstanceError):
        result.score = 1.0  # type: ignore[misc]
