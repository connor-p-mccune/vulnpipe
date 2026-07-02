"""Unit tests for SBOM analysis (component advisories -> findings).

Drives the analyzer with a fake OSV client so no network is touched, and asserts
on the normalized findings: identity, severity from the advisory CVSS, metadata,
remediation, and the skip path for un-queryable components.
"""

from vulnpipe.core.models import Severity
from vulnpipe.sbom.analyzer import SOURCE, analyze_sbom
from vulnpipe.sbom.cyclonedx import Component, Sbom
from vulnpipe.sbom.osv_client import OsvVulnerability


class _FakeOsv:
    """Return canned advisories keyed by (purl-base, version)."""

    def __init__(self, responses: dict[tuple[str, str], list[OsvVulnerability]]) -> None:
        self._responses = responses
        self.queries: list[tuple[str, str]] = []

    def query(self, purl: str, version: str) -> list[OsvVulnerability]:
        self.queries.append((purl, version))
        base = purl.rsplit("@", 1)[0]
        return self._responses.get((base, version), [])


_REQUESTS = Component(name="requests", version="2.19.0", purl="pkg:pypi/requests@2.19.0")
_VULN = OsvVulnerability(
    id="GHSA-x84v-xcm2-53pg",
    summary="Insufficiently protected credentials",
    aliases=("CVE-2018-18074", "PYSEC-2018-28"),
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    references=("https://nvd.nist.gov/vuln/detail/CVE-2018-18074",),
    fixed_versions=("2.20.0",),
)


def _sbom(*components: Component, subject: str = "acme-webapp") -> Sbom:
    return Sbom(subject=subject, components=tuple(components))


def test_advisory_becomes_a_normalized_finding() -> None:
    osv = _FakeOsv({("pkg:pypi/requests", "2.19.0"): [_VULN]})
    findings = analyze_sbom(_sbom(_REQUESTS), osv)  # type: ignore[arg-type]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.source == SOURCE
    assert finding.host == "acme-webapp"  # the SBOM subject is the identity
    assert finding.title == "GHSA-x84v-xcm2-53pg: requests 2.19.0"
    assert finding.plugin_id == "GHSA-x84v-xcm2-53pg"
    # CVSS:3.1 C:H vector -> base 7.5 -> High.
    assert finding.severity is Severity.HIGH
    assert finding.cvss_score == 7.5
    # Only real CVE ids survive normalization; the PYSEC alias is dropped.
    assert finding.cve_ids == ("CVE-2018-18074",)
    assert finding.solution == "Update requests to 2.20.0 or later."


def test_finding_metadata_carries_package_context() -> None:
    osv = _FakeOsv({("pkg:pypi/requests", "2.19.0"): [_VULN]})
    finding = analyze_sbom(_sbom(_REQUESTS), osv)[0]  # type: ignore[arg-type]
    assert finding.metadata["package"] == "requests"
    assert finding.metadata["package_version"] == "2.19.0"
    assert finding.metadata["ecosystem"] == "pypi"
    assert finding.metadata["purl"] == "pkg:pypi/requests@2.19.0"
    assert finding.metadata["aliases"] == ["CVE-2018-18074", "PYSEC-2018-28"]


def test_no_cvss_vector_stays_informational() -> None:
    plain = OsvVulnerability(id="OSV-1", summary="no score")
    osv = _FakeOsv({("pkg:pypi/requests", "2.19.0"): [plain]})
    finding = analyze_sbom(_sbom(_REQUESTS), osv)[0]  # type: ignore[arg-type]
    assert finding.severity is Severity.INFORMATIONAL  # unknown, never guessed
    assert finding.cvss_score is None
    assert finding.solution is None  # no fixed versions declared


def test_components_without_purl_or_version_are_skipped() -> None:
    osv = _FakeOsv({("pkg:pypi/requests", "2.19.0"): [_VULN]})
    sbom = _sbom(
        _REQUESTS,
        Component(name="no-version", purl="pkg:pypi/no-version"),  # missing version
        Component(name="vendored", version="1.0"),  # missing purl
    )
    findings = analyze_sbom(sbom, osv)  # type: ignore[arg-type]
    assert len(findings) == 1  # only the queryable component produced a finding
    assert osv.queries == [("pkg:pypi/requests@2.19.0", "2.19.0")]


def test_clean_component_yields_no_findings() -> None:
    osv = _FakeOsv({})  # OSV knows of nothing affecting it
    assert analyze_sbom(_sbom(_REQUESTS), osv) == []  # type: ignore[arg-type]


def test_findings_are_deterministic() -> None:
    osv = _FakeOsv({("pkg:pypi/requests", "2.19.0"): [_VULN]})
    first = analyze_sbom(_sbom(_REQUESTS), osv)  # type: ignore[arg-type]
    second = analyze_sbom(_sbom(_REQUESTS), osv)  # type: ignore[arg-type]
    assert [f.fingerprint for f in first] == [f.fingerprint for f in second]
