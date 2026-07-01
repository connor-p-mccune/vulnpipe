"""CISA KEV (Known Exploited Vulnerabilities) catalog client.

Cross-references CVE IDs against the U.S. CISA Known Exploited Vulnerabilities
catalog -- the authoritative list of vulnerabilities CISA has confirmed are being
*actively exploited in the wild*. A CVE in this catalog is a far stronger
prioritization signal than a high CVSS score alone: it is not "could be exploited"
but "is being exploited," which is why the enrichment stage flags such findings and
the prioritizer surfaces them first.

The whole catalog is a single JSON document, so this client fetches it once per run
(memoized in-process and cached on disk like the NVD/EPSS clients) and answers
membership questions from the parsed result. Response parsing
(:func:`parse_kev_catalog`) is a pure function so it can be unit-tested against a
captured catalog without any network access.

Honesty rules apply as everywhere else: a CVE that is *absent* from the catalog is
reported as not-known-exploited (``kev=False``) -- absence of evidence, never a
guess -- and a fetch failure degrades to an empty catalog with a logged warning
rather than aborting the pipeline or inventing exploitation status.
"""

import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from vulnpipe.core.config import Config
from vulnpipe.core.logging import get_logger, log_event
from vulnpipe.enrichment._http import (
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_TIMEOUT,
    CacheProtocol,
    HttpJsonClient,
    RetryableStatusError,
)
from vulnpipe.processing.normalizer import normalize_cve

_log = get_logger(__name__)

#: The canonical CISA KEV catalog feed (a single JSON document).
DEFAULT_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
#: Cache TTL for the catalog (1 day) -- CISA refreshes KEV roughly daily.
DEFAULT_CACHE_TTL_SECONDS = 24 * 60 * 60
#: Single disk-cache key: the catalog is fetched and stored whole, not per-CVE.
_CACHE_KEY = "kev:catalog"


@dataclass(frozen=True)
class KevEntry:
    """One CISA KEV catalog record; absent fields are unknown, not guessed."""

    cve_id: str
    vendor_project: str | None = None
    product: str | None = None
    vulnerability_name: str | None = None
    date_added: str | None = None
    short_description: str | None = None
    required_action: str | None = None
    due_date: str | None = None
    known_ransomware: bool = False


# --------------------------------------------------------------------------- #
# Pure parsing (no network)
# --------------------------------------------------------------------------- #
def _clean(value: Any) -> str | None:
    """Return a stripped non-empty string, or ``None``."""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _is_ransomware(value: Any) -> bool:
    """Map CISA's ``knownRansomwareCampaignUse`` field onto a boolean.

    The catalog uses the strings ``"Known"`` / ``"Unknown"``; anything other than a
    case-insensitive ``"known"`` is treated as not-known (the conservative reading).
    """
    return isinstance(value, str) and value.strip().lower() == "known"


def parse_kev_catalog(payload: Mapping[str, Any]) -> dict[str, KevEntry]:
    """Parse a CISA KEV catalog document into a ``{cve_id: KevEntry}`` mapping.

    Records without a valid CVE id are skipped rather than coerced, and the first
    occurrence of a CVE wins, so the result only ever contains real, canonical CVE
    ids. An unexpected shape yields an empty mapping (no exception).
    """
    entries: dict[str, KevEntry] = {}
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return entries
    for item in vulnerabilities:
        if not isinstance(item, Mapping):
            continue
        raw_id = item.get("cveID")
        cve = normalize_cve(raw_id) if isinstance(raw_id, str) else None
        if cve is None or cve in entries:
            continue
        entries[cve] = KevEntry(
            cve_id=cve,
            vendor_project=_clean(item.get("vendorProject")),
            product=_clean(item.get("product")),
            vulnerability_name=_clean(item.get("vulnerabilityName")),
            date_added=_clean(item.get("dateAdded")),
            short_description=_clean(item.get("shortDescription")),
            required_action=_clean(item.get("requiredAction")),
            due_date=_clean(item.get("dueDate")),
            known_ransomware=_is_ransomware(item.get("knownRansomwareCampaignUse")),
        )
    return entries


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #
class KevClient:
    """Fetch and query the CISA KEV catalog, fetched once and cached on disk.

    The catalog is loaded lazily on the first query and memoized for the life of the
    client (and persisted to the shared disk cache for a day). Failures degrade to an
    empty catalog with a logged warning rather than raising, so an unreachable feed
    never aborts the pipeline. The ``sleep`` callable is injectable so tests run
    without real delays.
    """

    def __init__(
        self,
        *,
        cache: CacheProtocol | None = None,
        base_url: str = DEFAULT_KEV_URL,
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
        self._catalog: dict[str, KevEntry] | None = None
        if http is not None:
            self._http = http
        else:
            self._http = HttpJsonClient(
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
    ) -> "KevClient | None":
        """Build a client from config, or ``None`` when KEV enrichment is disabled."""
        if not config.enrichment.kev_enabled:
            return None
        return cls(cache=cache, sleep=sleep)

    def get_catalog(self) -> dict[str, KevEntry]:
        """Return the parsed catalog, loading it once (memoized, then disk-cached)."""
        if self._catalog is not None:
            return self._catalog
        if self._cache is not None:
            cached = self._cache.get(_CACHE_KEY)
            if isinstance(cached, dict):
                self._catalog = cached
                return cached
        catalog = self._fetch_catalog()
        self._catalog = catalog
        if catalog and self._cache is not None:
            self._cache.set(_CACHE_KEY, catalog, expire=self._cache_ttl)
        return catalog

    def is_known_exploited(self, cve_id: str) -> bool:
        """Whether ``cve_id`` appears in the KEV catalog (False if unknown/invalid)."""
        normalized = normalize_cve(cve_id)
        return normalized is not None and normalized in self.get_catalog()

    def lookup(self, cve_id: str) -> KevEntry | None:
        """Return the :class:`KevEntry` for ``cve_id``, or ``None`` if not in KEV."""
        normalized = normalize_cve(cve_id)
        if normalized is None:
            return None
        return self.get_catalog().get(normalized)

    def _fetch_catalog(self) -> dict[str, KevEntry]:
        try:
            status, data = self._http.get_json(self._base_url)
        except (httpx.HTTPError, RetryableStatusError) as exc:
            log_event(_log, logging.WARNING, "kev catalog fetch failed", error=str(exc))
            return {}
        if status != 200:
            log_event(_log, logging.WARNING, "kev catalog returned non-200", status=status)
            return {}
        if not isinstance(data, Mapping):
            return {}
        catalog = parse_kev_catalog(data)
        log_event(_log, logging.INFO, "kev catalog loaded", entries=len(catalog))
        return catalog

    def close(self) -> None:
        self._http.close()


__all__ = [
    "DEFAULT_KEV_URL",
    "KevClient",
    "KevEntry",
    "parse_kev_catalog",
]
