"""OpenVEX 0.2.0 report renderer -- vulnerability exploitability statements.

Emits an `OpenVEX <https://openvex.dev>`_ document: the open standard for
communicating the *exploitability status* of vulnerabilities in a product. It is
the natural capstone to the SBOM + OSV supply-chain layer -- SBOM says what ships,
OSV says which components are vulnerable, and VEX states, machine-readably, that
those products are affected. Scanners like Trivy/Grype and CI policy engines consume
VEX to suppress or confirm advisories, so this lets a vulnpipe run feed that
ecosystem directly.

A few deliberate, honest choices:

* **Only known vulnerabilities.** A statement is emitted for a finding that cites a
  real vulnerability identifier -- a CVE, or (for a GHSA-only OSV advisory from the
  SBOM layer) its OSV id. Hygiene alerts and open-port observations that name no
  such identifier produce nothing: VEX speaks about known vulnerabilities, and
  inventing an identifier to force a statement would be dishonest.
* **Only the ``affected`` status.** Every finding is a *detection* that the product
  is affected, so that is the one status asserted. vulnpipe never emits
  ``not_affected`` / ``fixed`` -- those are human exploitability judgements it does
  not make; claiming them would fabricate an assessment.
* **Honest remediation.** ``action_statement`` repeats the scanner's / OSV's concrete
  fix verbatim when one exists; otherwise it carries neutral, clearly-generic
  guidance (never invented scan data). A vulnerability in the CISA KEV catalog gets
  a ``status_notes`` flag.

Deterministic for fixed input, like every other reporter: products within a
statement are sorted, statements follow first-seen order, and the document ``@id``
is content-addressed (a hash of the statements, so identical findings always yield
the same id). The one spec-mandated exception is the document ``timestamp``: OpenVEX
requires the publication time, which is inherently not a function of the findings.
:func:`build_vex` / :func:`render_vex` omit it unless one is passed (pure and
snapshot-friendly), while the registered reporter -- the path the CLI publishes
through -- stamps the real UTC time, honoring the reproducible-builds
``SOURCE_DATE_EPOCH`` convention so CI can still emit byte-identical documents.
"""

import hashlib
import json
import os
import re
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from vulnpipe.core.models import Finding
from vulnpipe.reporting.base import BaseReporter

#: The OpenVEX 0.2.0 JSON-LD context.
OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"

#: Prefix for the content-addressed document ``@id``.
_DOC_ID_PREFIX = "https://openvex.dev/docs/vulnpipe-"

#: Document revision. A freshly rendered report is always revision 1; a publisher
#: that re-issues an updated document is the one that bumps it.
_DOC_VERSION = 1

#: The only status vulnpipe asserts (see the module docstring).
STATUS_AFFECTED = "affected"

#: Neutral remediation used when neither the scanner nor OSV supplied a concrete fix.
_GENERIC_ACTION = "Review the referenced advisories and remediate the affected product."

#: Note added to a statement whose vulnerability is in the CISA KEV catalog.
_KEV_NOTE = (
    "A cited CVE is listed in the CISA Known Exploited Vulnerabilities catalog "
    "(actively exploited in the wild)."
)

#: RFC 3339 UTC layout for the document timestamp.
_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_GHSA_RE = re.compile(r"^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$", re.IGNORECASE)


def _vuln_ids(finding: Finding) -> tuple[str, ...]:
    """The vulnerability identifiers a finding makes a VEX statement about.

    Prefers CVEs (the canonical identifier); an advisory with no CVE (e.g. a
    GHSA-only OSV record from the SBOM layer) falls back to its OSV id. A finding
    that cites no vulnerability id yields nothing.
    """
    if finding.cve_ids:
        return finding.cve_ids
    osv_id = finding.metadata.get("osv_id")
    if isinstance(osv_id, str) and osv_id:
        return (osv_id,)
    return ()


def _vuln_reference(vuln_id: str) -> str | None:
    """A canonical URL for a vulnerability identifier, or ``None`` for unknown schemes."""
    if _CVE_RE.match(vuln_id):
        return f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
    if _GHSA_RE.match(vuln_id):
        return f"https://github.com/advisories/{vuln_id}"
    return None


def _vulnerability(vuln_id: str) -> dict[str, Any]:
    """The OpenVEX ``vulnerability`` object: its name plus a canonical URL when known."""
    vuln: dict[str, Any] = {"name": vuln_id}
    reference = _vuln_reference(vuln_id)
    if reference is not None:
        vuln["@id"] = reference
    return vuln


def _product(finding: Finding) -> dict[str, Any]:
    """The product a finding pertains to: a package URL when known, else host[:port].

    SBOM findings carry a real ``purl`` (also surfaced under ``identifiers`` so a
    consumer can key on it); network/web findings identify the affected asset by
    ``host`` or ``host:port``.
    """
    purl = finding.metadata.get("purl")
    if isinstance(purl, str) and purl:
        return {"@id": purl, "identifiers": {"purl": purl}}
    asset = finding.host if finding.port is None else f"{finding.host}:{finding.port}"
    return {"@id": asset}


def _action_statement(finding: Finding) -> str:
    """The concrete remediation for a finding, or neutral generic guidance."""
    solution = finding.solution
    if solution and solution.strip():
        return solution.strip()
    return _GENERIC_ACTION


def _document_id(statements: list[dict[str, Any]]) -> str:
    """A content-addressed document ``@id`` (a hash of the statements)."""
    canonical = json.dumps(statements, sort_keys=True, ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
    return f"{_DOC_ID_PREFIX}{digest}"


def _format_timestamp(timestamp: str | datetime | None) -> str | None:
    """Normalize a caller-supplied timestamp to an RFC 3339 UTC string, or ``None``.

    A naive :class:`~datetime.datetime` is taken as UTC; an aware one is converted.
    A string passes through verbatim (the caller has already chosen its form).
    """
    if timestamp is None:
        return None
    if isinstance(timestamp, datetime):
        moment = timestamp if timestamp.tzinfo is not None else timestamp.replace(tzinfo=UTC)
        return moment.astimezone(UTC).strftime(_TIMESTAMP_FORMAT)
    return timestamp


def _publication_timestamp() -> str:
    """The publication timestamp the registered reporter stamps documents with.

    Honors ``SOURCE_DATE_EPOCH`` (the reproducible-builds convention: seconds since
    the Unix epoch) when set, so CI and tests can produce byte-identical documents;
    otherwise the current UTC time. A malformed override is an error, not silently
    ignored -- a build that asks for reproducibility should get it or fail loudly.
    """
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch is not None:
        try:
            seconds = int(epoch)
        except ValueError as exc:
            raise ValueError(
                f"SOURCE_DATE_EPOCH must be an integer Unix timestamp, got {epoch!r}"
            ) from exc
        return datetime.fromtimestamp(seconds, tz=UTC).strftime(_TIMESTAMP_FORMAT)
    return datetime.now(tz=UTC).strftime(_TIMESTAMP_FORMAT)


def build_vex(
    findings: Iterable[Finding],
    *,
    author: str = "vulnpipe",
    timestamp: str | datetime | None = None,
) -> dict[str, Any]:
    """Build the OpenVEX 0.2.0 document for ``findings``.

    Findings are grouped into statements keyed by ``(vulnerability, action
    statement)`` so a concrete fix and the generic fallback for the same CVE stay
    distinct and no finding's real remediation text is lost. Products accumulate
    uniquely per group and are sorted; statements keep first-seen order.
    """
    items = list(findings)

    # Whether each vulnerability is known-exploited (a property of the CVE, OR-ed
    # across every finding that cites it -- never split into its own statement).
    kev_by_vuln: dict[str, bool] = {}
    for finding in items:
        for vuln_id in _vuln_ids(finding):
            kev_by_vuln[vuln_id] = kev_by_vuln.get(vuln_id, False) or finding.kev

    order: list[tuple[str, str]] = []
    grouped: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
    for finding in items:
        action = _action_statement(finding)
        product = _product(finding)
        product_id = str(product["@id"])
        for vuln_id in _vuln_ids(finding):
            key = (vuln_id, action)
            if key not in grouped:
                order.append(key)
                grouped[key] = {}
            grouped[key].setdefault(product_id, product)

    statements: list[dict[str, Any]] = []
    for vuln_id, action in order:
        products = grouped[(vuln_id, action)]
        statement: dict[str, Any] = {
            "vulnerability": _vulnerability(vuln_id),
            "products": [products[product_id] for product_id in sorted(products)],
            "status": STATUS_AFFECTED,
            "action_statement": action,
        }
        if kev_by_vuln.get(vuln_id):
            statement["status_notes"] = _KEV_NOTE
        statements.append(statement)

    document: dict[str, Any] = {
        "@context": OPENVEX_CONTEXT,
        "@id": _document_id(statements),
        "author": author,
    }
    stamped = _format_timestamp(timestamp)
    if stamped is not None:
        document["timestamp"] = stamped
    document["version"] = _DOC_VERSION
    document["statements"] = statements
    return document


def render_vex(
    findings: Iterable[Finding],
    *,
    author: str = "vulnpipe",
    timestamp: str | datetime | None = None,
) -> str:
    """Render ``findings`` into a deterministic OpenVEX 0.2.0 JSON document string."""
    document = build_vex(findings, author=author, timestamp=timestamp)
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


class VexReporter(BaseReporter):
    """Render findings into an OpenVEX 0.2.0 document stamped at publication time.

    This is the path the CLI publishes through, so the spec-required ``timestamp``
    is always present: from ``SOURCE_DATE_EPOCH`` when set (reproducible builds),
    otherwise the current UTC time. Everything else in the document is a pure
    function of the findings (see :func:`build_vex`).
    """

    name = "vex"

    def render(self, findings: list[Finding]) -> str:
        return render_vex(findings, timestamp=_publication_timestamp())


__all__ = [
    "OPENVEX_CONTEXT",
    "STATUS_AFFECTED",
    "VexReporter",
    "build_vex",
    "render_vex",
]
