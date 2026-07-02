"""OSV.dev client: known-vulnerability lookups for declared components.

`OSV <https://osv.dev/>`_ is the open, cross-ecosystem vulnerability database
(Google-operated, aggregating GitHub Security Advisories, PyPA, RustSec, and
more). Its ``/v1/query`` endpoint takes a package (as a purl) plus a version and
returns the advisories affecting it -- exactly the question SBOM analysis asks per
component. This is *detection via a real advisory source*: every finding the
analyzer builds traces to an OSV record, in line with the no-fabrication rule.

The client mirrors the NVD/EPSS/KEV enrichment clients: one small typed result
(:class:`OsvVulnerability`), pure response parsing (:func:`parse_osv_response`)
that is unit-testable from a captured fixture, per-``purl@version`` disk caching,
and failure degrading to an empty result with a logged warning rather than
aborting the run.
"""

import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from vulnpipe.core.logging import get_logger, log_event
from vulnpipe.enrichment._http import (
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_TIMEOUT,
    CacheProtocol,
    HttpJsonClient,
    RetryableStatusError,
)
from vulnpipe.enrichment.cvss import parse_vector

_log = get_logger(__name__)

#: The OSV.dev query endpoint (a JSON POST per package+version).
DEFAULT_OSV_URL = "https://api.osv.dev/v1/query"
#: Cache TTL for a per-package lookup (1 day; OSV updates continuously).
DEFAULT_CACHE_TTL_SECONDS = 24 * 60 * 60
_CACHE_PREFIX = "osv:"


@dataclass(frozen=True)
class OsvVulnerability:
    """One OSV advisory affecting a queried package; absent fields are unknown."""

    id: str
    summary: str | None = None
    aliases: tuple[str, ...] = ()
    cvss_vector: str | None = None
    references: tuple[str, ...] = ()
    fixed_versions: tuple[str, ...] = ()


def _clean(value: Any) -> str | None:
    """Return a stripped non-empty string, or ``None``."""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _purl_base(purl: str) -> str:
    """The purl without its version suffix (``pkg:npm/lodash@4.17.11`` -> ``pkg:npm/lodash``)."""
    return purl.rsplit("@", 1)[0] if "@" in purl else purl


def _worst_cvss_vector(entry: Mapping[str, Any]) -> str | None:
    """Pick the parseable CVSS vector with the highest base score from ``severity[]``.

    OSV lists zero or more ``{"type": "CVSS_V3", "score": "<vector>"}`` records; the
    worst case wins (consistent with the enrichment stage's multi-CVE rule). An
    unparseable vector is skipped, never guessed at.
    """
    severity = entry.get("severity")
    if not isinstance(severity, list):
        return None
    best: tuple[float, str] | None = None
    for item in severity:
        if not isinstance(item, Mapping):
            continue
        parsed = parse_vector(_clean(item.get("score")))
        if parsed is None:
            continue
        if best is None or parsed.score > best[0]:
            best = (parsed.score, parsed.vector)
    return best[1] if best is not None else None


def _fixed_versions(entry: Mapping[str, Any], purl: str) -> tuple[str, ...]:
    """Collect the ``fixed`` version events for the queried package, in seen order.

    Only ``affected[]`` entries matching the queried purl contribute (an OSV record
    can span ecosystems); entries that carry no purl are included leniently since
    the record was returned for this package's query.
    """
    base = _purl_base(purl)
    fixed: dict[str, None] = {}
    affected = entry.get("affected")
    if not isinstance(affected, list):
        return ()
    for item in affected:
        if not isinstance(item, Mapping):
            continue
        package = item.get("package")
        entry_purl = package.get("purl") if isinstance(package, Mapping) else None
        if isinstance(entry_purl, str) and _purl_base(entry_purl) != base:
            continue
        ranges = item.get("ranges")
        if not isinstance(ranges, list):
            continue
        for range_item in ranges:
            if not isinstance(range_item, Mapping):
                continue
            events = range_item.get("events")
            if not isinstance(events, list):
                continue
            for event in events:
                if isinstance(event, Mapping):
                    version = _clean(event.get("fixed"))
                    if version is not None and version not in fixed:
                        fixed[version] = None
    return tuple(fixed)


def _references(entry: Mapping[str, Any]) -> tuple[str, ...]:
    """Reference URLs in seen order, de-duplicated."""
    references = entry.get("references")
    if not isinstance(references, list):
        return ()
    urls: dict[str, None] = {}
    for item in references:
        if isinstance(item, Mapping):
            url = _clean(item.get("url"))
            if url is not None and url not in urls:
                urls[url] = None
    return tuple(urls)


def _aliases(entry: Mapping[str, Any]) -> tuple[str, ...]:
    """Alias identifiers (CVE ids, GHSA ids, ...) in seen order, de-duplicated."""
    aliases = entry.get("aliases")
    if not isinstance(aliases, list):
        return ()
    seen: dict[str, None] = {}
    for item in aliases:
        alias = _clean(item) if isinstance(item, str) else None
        if alias is not None and alias not in seen:
            seen[alias] = None
    return tuple(seen)


def parse_osv_response(payload: Mapping[str, Any], *, purl: str) -> list[OsvVulnerability]:
    """Parse an OSV ``/v1/query`` response into vulnerabilities, sorted by id.

    Records without an id are skipped rather than coerced. Sorting by id makes the
    result (and everything built on it) deterministic regardless of API ordering.
    """
    vulns = payload.get("vulns")
    if not isinstance(vulns, list):
        return []
    parsed: dict[str, OsvVulnerability] = {}
    for entry in vulns:
        if not isinstance(entry, Mapping):
            continue
        vuln_id = _clean(entry.get("id"))
        if vuln_id is None or vuln_id in parsed:
            continue
        parsed[vuln_id] = OsvVulnerability(
            id=vuln_id,
            summary=_clean(entry.get("summary")),
            aliases=_aliases(entry),
            cvss_vector=_worst_cvss_vector(entry),
            references=_references(entry),
            fixed_versions=_fixed_versions(entry, purl),
        )
    return [parsed[vuln_id] for vuln_id in sorted(parsed)]


class OsvClient:
    """Query OSV.dev per package, cached on disk like the enrichment clients.

    Failures degrade to an empty result with a logged warning rather than raising,
    so an unreachable advisory service never aborts an analysis; the affected
    component is simply reported without advisories (unknown, not clean).
    """

    def __init__(
        self,
        *,
        cache: CacheProtocol | None = None,
        base_url: str = DEFAULT_OSV_URL,
        cache_ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS,
        http: HttpJsonClient | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        min_request_interval: float = 0.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._base_url = base_url
        self._cache = cache
        self._cache_ttl = cache_ttl_seconds
        if http is not None:
            self._http = http
        else:
            self._http = HttpJsonClient(
                min_request_interval=min_request_interval,
                timeout=timeout,
                max_attempts=max_attempts,
                sleep=sleep,
            )

    def query(self, purl: str, version: str) -> list[OsvVulnerability]:
        """Return the advisories affecting ``purl`` at ``version`` (cached, sorted).

        The purl is queried without its version suffix and the version is passed
        separately, per the OSV query contract.
        """
        cache_key = f"{_CACHE_PREFIX}{_purl_base(purl)}@{version}"
        if self._cache is not None:
            cached = self._cache.get(cache_key)
            if isinstance(cached, list):
                return cached
        result = self._query_api(purl, version)
        if self._cache is not None:
            self._cache.set(cache_key, result, expire=self._cache_ttl)
        return result

    def _query_api(self, purl: str, version: str) -> list[OsvVulnerability]:
        body = {"package": {"purl": _purl_base(purl)}, "version": version}
        try:
            status, data = self._http.post_json(self._base_url, json_body=body)
        except (httpx.HTTPError, RetryableStatusError) as exc:
            log_event(_log, logging.WARNING, "osv query failed", purl=purl, error=str(exc))
            return []
        if status != 200:
            log_event(_log, logging.WARNING, "osv query returned non-200", status=status)
            return []
        if not isinstance(data, Mapping):
            return []
        return parse_osv_response(data, purl=purl)

    def close(self) -> None:
        self._http.close()


__all__ = [
    "DEFAULT_OSV_URL",
    "OsvClient",
    "OsvVulnerability",
    "parse_osv_response",
]
