"""Unit tests for the OWASP Top 10 / CWE Top 25 standards mapping.

The mapping is pure reference data plus pure lookups, so these tests cover the
data's structural invariants (every category present, no CWE in two categories),
the lenient CWE parsing, and the aggregate lookups reporters rely on.
"""

from vulnpipe.core.standards import (
    CWE_TOP_25_2023,
    OWASP_TOP_10_2021,
    OwaspCategory,
    cwe_top_25,
    is_cwe_top_25,
    owasp_categories,
    owasp_category_for_cwe,
    parse_cwe,
)


# --------------------------------------------------------------------------- #
# Reference-data invariants
# --------------------------------------------------------------------------- #
def test_top_10_lists_all_ten_categories_in_rank_order() -> None:
    assert len(OWASP_TOP_10_2021) == 10
    assert [category.rank for category in OWASP_TOP_10_2021] == list(range(1, 11))
    assert OWASP_TOP_10_2021[0].id == "A01:2021"
    assert OWASP_TOP_10_2021[2].title == "Injection"
    assert OWASP_TOP_10_2021[9].id == "A10:2021"


def test_category_short_code_and_label() -> None:
    injection = OWASP_TOP_10_2021[2]
    assert injection.short == "A03"
    assert injection.label == "A03 Injection"


def test_every_mapped_cwe_belongs_to_exactly_one_category() -> None:
    seen: dict[int, str] = {}
    for category in OWASP_TOP_10_2021:
        for offset in range(1, 1400):
            resolved = owasp_category_for_cwe(offset)
            if resolved is not None and resolved.id == category.id:
                assert seen.setdefault(offset, category.id) == category.id
    assert seen  # the map is non-empty


def test_cwe_top_25_has_25_distinct_entries() -> None:
    assert len(CWE_TOP_25_2023) == 25
    assert len(set(CWE_TOP_25_2023)) == 25
    assert CWE_TOP_25_2023[0] == 787  # out-of-bounds write leads the 2023 list


# --------------------------------------------------------------------------- #
# parse_cwe
# --------------------------------------------------------------------------- #
def test_parse_cwe_accepts_common_forms() -> None:
    assert parse_cwe("CWE-79") == 79
    assert parse_cwe("cwe-89") == 89
    assert parse_cwe(" 22 ") == 22
    assert parse_cwe(917) == 917


def test_parse_cwe_rejects_non_cwe_tokens() -> None:
    assert parse_cwe(None) is None
    assert parse_cwe(True) is None
    assert parse_cwe("NVD-CWE-noinfo") is None
    assert parse_cwe("-1") is None
    assert parse_cwe("0") is None
    assert parse_cwe("CWE-0") is None
    assert parse_cwe("") is None


# --------------------------------------------------------------------------- #
# Lookups
# --------------------------------------------------------------------------- #
def test_known_cwes_map_to_the_official_categories() -> None:
    xss = owasp_category_for_cwe(79)
    assert isinstance(xss, OwaspCategory) and xss.id == "A03:2021"
    assert owasp_category_for_cwe(918).id == "A10:2021"  # type: ignore[union-attr]
    assert owasp_category_for_cwe(287).id == "A07:2021"  # type: ignore[union-attr]
    assert owasp_category_for_cwe(200).id == "A01:2021"  # type: ignore[union-attr]
    assert owasp_category_for_cwe(532).id == "A09:2021"  # type: ignore[union-attr]


def test_unmapped_cwe_returns_none_rather_than_a_guess() -> None:
    assert owasp_category_for_cwe(99999) is None


def test_owasp_categories_deduplicates_and_orders_by_rank() -> None:
    # 918 (A10) listed before 79/89 (A03): result must come back in rank order.
    categories = owasp_categories(["CWE-918", "CWE-79", "cwe-89", "CWE-79"])
    assert [category.short for category in categories] == ["A03", "A10"]


def test_owasp_categories_ignores_invalid_and_unmapped_ids() -> None:
    assert owasp_categories(["nonsense", "NVD-CWE-noinfo", "CWE-99999"]) == ()
    assert owasp_categories([]) == ()


def test_is_cwe_top_25() -> None:
    assert is_cwe_top_25(79) is True
    assert is_cwe_top_25(787) is True
    assert is_cwe_top_25(1275) is False


def test_cwe_top_25_filter_preserves_first_seen_order() -> None:
    assert cwe_top_25(["CWE-89", "CWE-79", "CWE-89", "CWE-1275"]) == (89, 79)
    assert cwe_top_25(["garbage", "CWE-1275"]) == ()
