"""Map weaknesses (CWE) onto industry standards: OWASP Top 10 and the CWE Top 25.

Findings often carry one or more CWE references (from ZAP alerts, NVD metadata, or
the KEV catalog). On their own a bare ``CWE-79`` means little to a reviewer; mapped
onto the frameworks people actually report against it becomes "this is an *A03:2021
Injection* issue, and one of the *CWE Top 25 Most Dangerous Weaknesses*." This
module holds that mapping as pure, sourced reference data plus small pure lookups,
so the reporting layer can group findings by OWASP category and flag the most
dangerous weakness classes without any I/O.

Honesty rules apply here as everywhere else. The category assignments are a curated
subset of the official OWASP Top 10 2021 CWE mapping and the 2023 CWE Top 25 list --
real, published associations, not invented ones. A CWE that is not in the curated
map returns no category (the finding is reported as *unmapped*) rather than being
forced into a bucket it does not belong to.

References:

* OWASP Top 10 2021 -- https://owasp.org/Top10/
* 2023 CWE Top 25 -- https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass

_CWE_RE = re.compile(r"(?:CWE-)?(\d+)", re.IGNORECASE)


@dataclass(frozen=True)
class OwaspCategory:
    """One OWASP Top 10 2021 category, ordered by :attr:`rank` (A01 first)."""

    id: str
    rank: int
    title: str

    @property
    def short(self) -> str:
        """The short code without the year, e.g. ``A03`` for ``A03:2021``."""
        return self.id.split(":", 1)[0]

    @property
    def label(self) -> str:
        """A compact display label, e.g. ``A03 Injection``."""
        return f"{self.short} {self.title}"


#: The OWASP Top 10 2021 categories in rank order (A01 = most prevalent).
OWASP_TOP_10_2021: tuple[OwaspCategory, ...] = (
    OwaspCategory("A01:2021", 1, "Broken Access Control"),
    OwaspCategory("A02:2021", 2, "Cryptographic Failures"),
    OwaspCategory("A03:2021", 3, "Injection"),
    OwaspCategory("A04:2021", 4, "Insecure Design"),
    OwaspCategory("A05:2021", 5, "Security Misconfiguration"),
    OwaspCategory("A06:2021", 6, "Vulnerable and Outdated Components"),
    OwaspCategory("A07:2021", 7, "Identification and Authentication Failures"),
    OwaspCategory("A08:2021", 8, "Software and Data Integrity Failures"),
    OwaspCategory("A09:2021", 9, "Security Logging and Monitoring Failures"),
    OwaspCategory("A10:2021", 10, "Server-Side Request Forgery (SSRF)"),
)

_CATEGORY_BY_ID: dict[str, OwaspCategory] = {
    category.id: category for category in OWASP_TOP_10_2021
}

#: Curated CWE membership per OWASP Top 10 2021 category. Each CWE belongs to exactly
#: one category (as in the official mapping); the reverse index is built below.
_CATEGORY_CWES: dict[str, tuple[int, ...]] = {
    "A01:2021": (
        22,
        23,
        35,
        59,
        200,
        201,
        219,
        275,
        276,
        284,
        285,
        352,
        359,
        377,
        402,
        425,
        441,
        497,
        538,
        540,
        548,
        552,
        566,
        601,
        639,
        651,
        668,
        706,
        862,
        863,
        913,
        922,
        1275,
    ),
    "A02:2021": (
        261,
        296,
        310,
        311,
        312,
        313,
        316,
        319,
        321,
        322,
        323,
        324,
        325,
        326,
        327,
        328,
        329,
        330,
        331,
        335,
        336,
        337,
        338,
        340,
        523,
        720,
        757,
        759,
        760,
        780,
        818,
        916,
    ),
    "A03:2021": (
        20,
        74,
        75,
        77,
        78,
        79,
        80,
        83,
        87,
        88,
        89,
        90,
        91,
        93,
        94,
        95,
        96,
        97,
        98,
        99,
        100,
        113,
        116,
        138,
        184,
        470,
        471,
        564,
        610,
        643,
        644,
        652,
        917,
    ),
    "A04:2021": (
        73,
        183,
        209,
        213,
        235,
        256,
        257,
        266,
        269,
        280,
        419,
        430,
        434,
        444,
        451,
        472,
        501,
        525,
        539,
        579,
        598,
        602,
        642,
        646,
        650,
        653,
        656,
        657,
        799,
        807,
        840,
        841,
        927,
        1021,
        1173,
    ),
    "A05:2021": (
        2,
        11,
        13,
        15,
        16,
        260,
        315,
        520,
        526,
        537,
        541,
        547,
        611,
        614,
        756,
        776,
        942,
        1004,
        1032,
        1174,
    ),
    "A06:2021": (937, 1035, 1104),
    "A07:2021": (
        255,
        259,
        287,
        288,
        290,
        294,
        295,
        297,
        300,
        302,
        304,
        306,
        307,
        346,
        384,
        521,
        522,
        613,
        620,
        640,
        798,
        940,
        1216,
    ),
    "A08:2021": (345, 347, 353, 426, 494, 502, 565, 784, 829, 830, 915),
    "A09:2021": (117, 223, 532, 778),
    "A10:2021": (918,),
}

#: Reverse index: CWE number -> its OWASP category.
_CWE_TO_CATEGORY: dict[int, OwaspCategory] = {
    cwe: _CATEGORY_BY_ID[category_id]
    for category_id, cwes in _CATEGORY_CWES.items()
    for cwe in cwes
}

#: The 2023 CWE Top 25 Most Dangerous Software Weaknesses, in rank order.
CWE_TOP_25_2023: tuple[int, ...] = (
    787,
    79,
    89,
    416,
    78,
    20,
    125,
    22,
    352,
    434,
    862,
    476,
    287,
    190,
    502,
    77,
    119,
    798,
    918,
    306,
    362,
    269,
    94,
    863,
    276,
)

_CWE_TOP_25_SET: frozenset[int] = frozenset(CWE_TOP_25_2023)


def parse_cwe(value: str | int | None) -> int | None:
    """Return the CWE number from ``value`` (``"CWE-79"`` / ``"79"`` / ``79``), or ``None``.

    Case-insensitive and whitespace-tolerant. Anything that is not a positive CWE
    number -- ``"NVD-CWE-noinfo"``, ``"-1"``, ``"0"``, a bool -- yields ``None`` so a
    non-CWE token is never coerced into one.
    """
    if value is None or isinstance(value, bool):
        return None
    match = _CWE_RE.fullmatch(str(value).strip())
    if match is None:
        return None
    number = int(match.group(1))
    return number if number > 0 else None


def owasp_category_for_cwe(cwe: int) -> OwaspCategory | None:
    """Return the OWASP Top 10 2021 category for a CWE number, or ``None`` if unmapped."""
    return _CWE_TO_CATEGORY.get(cwe)


def is_cwe_top_25(cwe: int) -> bool:
    """Whether ``cwe`` is one of the 2023 CWE Top 25 Most Dangerous Weaknesses."""
    return cwe in _CWE_TOP_25_SET


def owasp_categories(cwe_ids: Iterable[str]) -> tuple[OwaspCategory, ...]:
    """Return the distinct OWASP categories the given CWE ids map to, in rank order.

    CWE ids are parsed leniently and de-duplicated; unmappable or unknown ids are
    ignored. The result is ordered by OWASP rank so output is deterministic.
    """
    found: set[OwaspCategory] = set()
    for raw in cwe_ids:
        cwe = parse_cwe(raw)
        if cwe is None:
            continue
        category = _CWE_TO_CATEGORY.get(cwe)
        if category is not None:
            found.add(category)
    return tuple(sorted(found, key=lambda category: category.rank))


def cwe_top_25(cwe_ids: Iterable[str]) -> tuple[int, ...]:
    """Return the CWE numbers among ``cwe_ids`` that are in the 2023 CWE Top 25.

    Preserves first-seen order and de-duplicates, so a finding citing the same CWE
    twice reports it once.
    """
    seen: dict[int, None] = {}
    for raw in cwe_ids:
        cwe = parse_cwe(raw)
        if cwe is not None and cwe in _CWE_TOP_25_SET and cwe not in seen:
            seen[cwe] = None
    return tuple(seen)


__all__ = [
    "CWE_TOP_25_2023",
    "OWASP_TOP_10_2021",
    "OwaspCategory",
    "cwe_top_25",
    "is_cwe_top_25",
    "owasp_categories",
    "owasp_category_for_cwe",
    "parse_cwe",
]
