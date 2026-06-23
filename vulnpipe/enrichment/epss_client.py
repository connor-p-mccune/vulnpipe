"""EPSS (Exploit Prediction Scoring System) client.

Fetches EPSS probabilities and percentiles for CVE IDs from the FIRST.org API,
batching many CVEs per request and caching per-CVE results on disk (see
:mod:`vulnpipe.enrichment._http`). A CVE for which FIRST.org has no score is
simply absent from the result, so the enrichment step leaves its EPSS fields
unknown -- scores are never invented.

Response parsing (:func:`parse_epss_response`) is a pure function for unit
testing without network access. EPSS values are probabilities in ``[0, 1]``;
anything outside that range (or unparseable) is treated as unknown.
"""

import logging
import time
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
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

DEFAULT_EPSS_URL = "https://api.first.org/data/v1/epss"
#: Cache TTL for an EPSS score (1 day) -- FIRST.org refreshes EPSS daily.
DEFAULT_CACHE_TTL_SECONDS = 24 * 60 * 60
#: How many CVEs to request per API call.
DEFAULT_BATCH_SIZE = 100
_CACHE_PREFIX = "epss:"


@dataclass(frozen=True)
class EpssScore:
    """An EPSS probability (and percentile, if supplied) for a single CVE."""

    cve_id: str
    epss: float
    percentile: float | None = None


# --------------------------------------------------------------------------- #
# Pure parsing (no network)
# --------------------------------------------------------------------------- #
def _parse_unit_float(value: Any) -> float | None:
    """Parse a probability string/number in ``[0, 1]``; otherwise ``None``."""
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number != number:  # NaN
        return None
    if not 0.0 <= number <= 1.0:
        return None
    return number


def parse_epss_response(payload: Mapping[str, Any]) -> dict[str, EpssScore]:
    """Parse a FIRST.org EPSS response into a ``{cve_id: EpssScore}`` mapping.

    Entries without a valid CVE id or a valid EPSS probability are skipped rather
    than coerced, so the result only ever contains real, in-range scores.
    """
    scores: dict[str, EpssScore] = {}
    data = payload.get("data")
    if not isinstance(data, list):
        return scores
    for entry in data:
        if not isinstance(entry, Mapping):
            continue
        raw_cve = entry.get("cve")
        cve = normalize_cve(raw_cve) if isinstance(raw_cve, str) else None
        if cve is None:
            continue
        score = _parse_unit_float(entry.get("epss"))
        if score is None:
            continue
        scores[cve] = EpssScore(
            cve_id=cve,
            epss=score,
            percentile=_parse_unit_float(entry.get("percentile")),
        )
    return scores


def _chunked(items: Sequence[str], size: int) -> Iterator[list[str]]:
    for start in range(0, len(items), size):
        yield list(items[start : start + size])


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #
class EpssClient:
    """Fetch EPSS scores from FIRST.org, batched and cached on disk.

    Failures degrade to a partial (or empty) result with a logged warning rather
    than raising, so a flaky EPSS service never aborts the pipeline.
    """

    def __init__(
        self,
        *,
        cache: CacheProtocol | None = None,
        base_url: str = DEFAULT_EPSS_URL,
        cache_ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS,
        batch_size: int = DEFAULT_BATCH_SIZE,
        http: HttpJsonClient | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        min_request_interval: float = 0.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._base_url = base_url
        self._cache = cache
        self._cache_ttl = cache_ttl_seconds
        self._batch_size = max(1, batch_size)
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
    ) -> "EpssClient | None":
        """Build a client from config, or ``None`` when EPSS enrichment is disabled."""
        if not config.enrichment.epss_enabled:
            return None
        return cls(cache=cache, sleep=sleep)

    def get_scores(self, cve_ids: Iterable[str]) -> dict[str, EpssScore]:
        """Return ``{cve_id: EpssScore}`` for the known CVEs among ``cve_ids``.

        Input is normalized and de-duplicated; cached scores are reused and only
        the remainder is fetched (in batches). CVEs with no EPSS data are simply
        omitted from the result.
        """
        normalized: list[str] = []
        seen: set[str] = set()
        for raw in cve_ids:
            cve = normalize_cve(raw)
            if cve is not None and cve not in seen:
                seen.add(cve)
                normalized.append(cve)
        if not normalized:
            return {}

        results: dict[str, EpssScore] = {}
        missing: list[str] = []
        for cve in normalized:
            cached = self._cache.get(_CACHE_PREFIX + cve) if self._cache is not None else None
            if isinstance(cached, EpssScore):
                results[cve] = cached
            else:
                missing.append(cve)

        for chunk in _chunked(missing, self._batch_size):
            for cve, score in self._fetch_batch(chunk).items():
                # Cache every score the API returned, but only surface the ones
                # the caller actually asked for.
                if self._cache is not None:
                    self._cache.set(_CACHE_PREFIX + cve, score, expire=self._cache_ttl)
                if cve in seen:
                    results[cve] = score
        return results

    def _fetch_batch(self, cves: Sequence[str]) -> dict[str, EpssScore]:
        if not cves:
            return {}
        try:
            status, data = self._http.get_json(self._base_url, params={"cve": ",".join(cves)})
        except (httpx.HTTPError, RetryableStatusError) as exc:
            log_event(_log, logging.WARNING, "epss lookup failed", count=len(cves), error=str(exc))
            return {}
        if status != 200:
            log_event(_log, logging.WARNING, "epss lookup returned non-200", status=status)
            return {}
        if not isinstance(data, Mapping):
            return {}
        return parse_epss_response(data)

    def close(self) -> None:
        self._http.close()


__all__ = [
    "DEFAULT_EPSS_URL",
    "EpssClient",
    "EpssScore",
    "parse_epss_response",
]
