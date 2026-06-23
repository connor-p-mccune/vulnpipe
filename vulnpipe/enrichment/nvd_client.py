"""NVD (National Vulnerability Database) CVE lookup client.

Looks up CVE metadata from the NVD 2.0 REST API over HTTP, caching responses on
disk and backing off on transient failures (see :mod:`vulnpipe.enrichment._http`).
An API key, if configured, is read from the environment at construction time --
never from the config file -- and raises the request budget under NVD's published
rate limits. A lookup that fails or finds nothing returns ``None`` so the
enrichment step leaves the finding's fields unknown rather than guessing.

The response parsing (:func:`parse_nvd_response`) is a pure function so it can be
unit-tested against a captured NVD payload without any network access. When a
CVE carries several CVSS metric versions, the highest-fidelity one is chosen
(v3.1 > v3.0 > v4.0 > v2), preferring the Primary source within that version. The
chosen vector is re-scored through :mod:`vulnpipe.enrichment.cvss`; if the vector
will not parse, only NVD's own base score is salvaged (no invalid vector is kept).
"""

import logging
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from vulnpipe.core.config import Config, resolve_secret
from vulnpipe.core.logging import get_logger, log_event
from vulnpipe.enrichment._http import (
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_TIMEOUT,
    CacheProtocol,
    HttpJsonClient,
    RetryableStatusError,
)
from vulnpipe.enrichment.cvss import parse_vector
from vulnpipe.processing.normalizer import normalize_cve, parse_cvss

_log = get_logger(__name__)

DEFAULT_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
#: Cache TTL for an NVD record (7 days) -- CVE metadata changes slowly.
DEFAULT_CACHE_TTL_SECONDS = 7 * 24 * 60 * 60

#: Inter-request spacing (seconds) under NVD's published rate limits.
_INTERVAL_WITH_KEY = 0.6  # ~50 requests / 30s
_INTERVAL_WITHOUT_KEY = 6.0  # ~5 requests / 30s

_CACHE_PREFIX = "nvd:"
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)

# Preference order when a CVE carries several CVSS metric versions.
_METRIC_KEYS: tuple[tuple[str, str], ...] = (
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV2", "2.0"),
)


@dataclass(frozen=True)
class CveDetail:
    """Parsed NVD detail for a single CVE; absent fields are unknown, not guessed."""

    cve_id: str
    description: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    cwe_ids: tuple[str, ...] = ()
    references: tuple[str, ...] = ()


# --------------------------------------------------------------------------- #
# Pure parsing (no network)
# --------------------------------------------------------------------------- #
def _english_description(cve: Mapping[str, Any]) -> str | None:
    descriptions = cve.get("descriptions")
    if not isinstance(descriptions, list):
        return None
    fallback: str | None = None
    for entry in descriptions:
        if not isinstance(entry, Mapping):
            continue
        value = entry.get("value")
        if not isinstance(value, str) or not value.strip():
            continue
        if entry.get("lang") == "en":
            return value.strip()
        if fallback is None:
            fallback = value.strip()
    return fallback


def _choose_entry(entries: list[Any]) -> Mapping[str, Any] | None:
    """Prefer the Primary metric entry; otherwise the first well-formed one."""
    first: Mapping[str, Any] | None = None
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        if first is None:
            first = entry
        if entry.get("type") == "Primary":
            return entry
    return first


def _select_metric(metrics: Mapping[str, Any]) -> tuple[Mapping[str, Any], str] | None:
    for key, version in _METRIC_KEYS:
        entries = metrics.get(key)
        if not isinstance(entries, list):
            continue
        chosen = _choose_entry(entries)
        if chosen is None:
            continue
        data = chosen.get("cvssData")
        if isinstance(data, Mapping):
            return data, version
    return None


def _extract_cvss(cve: Mapping[str, Any]) -> tuple[float | None, str | None, str | None]:
    metrics = cve.get("metrics")
    if not isinstance(metrics, Mapping):
        return None, None, None
    selected = _select_metric(metrics)
    if selected is None:
        return None, None, None
    data, version = selected
    raw_vector = data.get("vectorString")
    vector = raw_vector if isinstance(raw_vector, str) else None
    parsed = parse_vector(vector)
    if parsed is not None:
        return parsed.score, parsed.vector, parsed.version
    # Vector missing/unparseable: salvage only NVD's own validated base score; do
    # not emit a vector string we could not parse (it would be misleading).
    score = parse_cvss(data.get("baseScore"))
    if score is None:
        return None, None, None
    return score, None, version


def _extract_cwes(cve: Mapping[str, Any]) -> tuple[str, ...]:
    weaknesses = cve.get("weaknesses")
    if not isinstance(weaknesses, list):
        return ()
    found: dict[str, None] = {}
    for weakness in weaknesses:
        if not isinstance(weakness, Mapping):
            continue
        descriptions = weakness.get("description")
        if not isinstance(descriptions, list):
            continue
        for desc in descriptions:
            if not isinstance(desc, Mapping):
                continue
            value = desc.get("value")
            if isinstance(value, str) and _CWE_RE.fullmatch(value.strip()):
                found[value.strip().upper()] = None
    return tuple(found)


def _extract_references(cve: Mapping[str, Any]) -> tuple[str, ...]:
    references = cve.get("references")
    if not isinstance(references, list):
        return ()
    found: dict[str, None] = {}
    for reference in references:
        if not isinstance(reference, Mapping):
            continue
        url = reference.get("url")
        if isinstance(url, str) and url.strip():
            found[url.strip()] = None
    return tuple(found)


def parse_nvd_response(payload: Mapping[str, Any], cve_id: str) -> CveDetail | None:
    """Parse an NVD 2.0 response, returning the detail for ``cve_id`` or ``None``.

    Scans ``vulnerabilities`` for the matching CVE and extracts its description,
    best CVSS metric, CWE ids, and references. Returns ``None`` when the payload
    has no matching vulnerability.
    """
    target = normalize_cve(cve_id)
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return None
    for item in vulnerabilities:
        if not isinstance(item, Mapping):
            continue
        cve = item.get("cve")
        if not isinstance(cve, Mapping):
            continue
        raw_id = cve.get("id")
        found_id = normalize_cve(raw_id) if isinstance(raw_id, str) else None
        if found_id is None or (target is not None and found_id != target):
            continue
        score, vector, version = _extract_cvss(cve)
        return CveDetail(
            cve_id=found_id,
            description=_english_description(cve),
            cvss_score=score,
            cvss_vector=vector,
            cvss_version=version,
            cwe_ids=_extract_cwes(cve),
            references=_extract_references(cve),
        )
    return None


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #
class NvdClient:
    """Look up CVE detail from the NVD 2.0 API, cached on disk and rate-limited.

    Failures degrade to ``None`` (a logged warning) rather than raising, so a flaky
    NVD never aborts the pipeline. Successful lookups are cached; the ``sleep``
    callable is injectable so tests run without real delays.
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        cache: CacheProtocol | None = None,
        base_url: str = DEFAULT_NVD_URL,
        cache_ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS,
        min_request_interval: float | None = None,
        http: HttpJsonClient | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._base_url = base_url
        self._cache = cache
        self._cache_ttl = cache_ttl_seconds
        if http is not None:
            self._http = http
        else:
            if min_request_interval is None:
                min_request_interval = _INTERVAL_WITH_KEY if api_key else _INTERVAL_WITHOUT_KEY
            headers = {"apiKey": api_key} if api_key else None
            self._http = HttpJsonClient(
                headers=headers,
                min_request_interval=min_request_interval,
                timeout=timeout,
                max_attempts=max_attempts,
                sleep=sleep,
            )

    @classmethod
    def from_config(
        cls,
        config: Config,
        *,
        cache: CacheProtocol | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> "NvdClient | None":
        """Build a client from config, or ``None`` when NVD enrichment is disabled."""
        enrichment = config.enrichment
        if not enrichment.nvd_enabled:
            return None
        api_key = resolve_secret(enrichment.nvd_api_key_env, required=False)
        return cls(api_key=api_key, cache=cache, sleep=sleep)

    def get_cve(self, cve_id: str) -> CveDetail | None:
        """Return cached/fetched detail for ``cve_id`` (``None`` if unknown/failed)."""
        normalized = normalize_cve(cve_id)
        if normalized is None:
            return None
        cache_key = _CACHE_PREFIX + normalized
        if self._cache is not None:
            cached = self._cache.get(cache_key)
            if isinstance(cached, CveDetail):
                return cached
        detail = self._fetch_cve(normalized)
        if detail is not None and self._cache is not None:
            self._cache.set(cache_key, detail, expire=self._cache_ttl)
        return detail

    def _fetch_cve(self, cve_id: str) -> CveDetail | None:
        try:
            status, data = self._http.get_json(self._base_url, params={"cveId": cve_id})
        except (httpx.HTTPError, RetryableStatusError) as exc:
            log_event(_log, logging.WARNING, "nvd lookup failed", cve=cve_id, error=str(exc))
            return None
        if status != 200:
            if status != 404:
                log_event(
                    _log, logging.WARNING, "nvd lookup returned non-200", cve=cve_id, status=status
                )
            return None
        if not isinstance(data, Mapping):
            return None
        return parse_nvd_response(data, cve_id)

    def close(self) -> None:
        self._http.close()


__all__ = [
    "DEFAULT_NVD_URL",
    "CveDetail",
    "NvdClient",
    "parse_nvd_response",
]
