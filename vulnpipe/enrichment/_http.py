"""Shared HTTP machinery for the NVD and EPSS enrichment clients.

Centralizes the cross-cutting concerns both clients need:

* a disk-backed response cache (:func:`open_cache`, backed by ``diskcache``),
* retry-with-backoff on transient failures (``tenacity``), and
* a simple inter-request throttle so we respect upstream rate limits.

The clients themselves only build request parameters and parse the JSON they get
back. Network failures surface here as exceptions; the calling client catches
them and degrades the affected lookup to "unknown" rather than crashing the
pipeline or inventing data. The ``sleep`` callable is injectable so tests run
without real delays.
"""

import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Protocol

import diskcache
import httpx
from tenacity import (
    Retrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

#: HTTP status codes worth retrying (rate limiting + transient server errors).
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})

DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_ATTEMPTS = 4
_BACKOFF_MULTIPLIER = 0.5
_BACKOFF_MAX = 30.0
_USER_AGENT = "vulnpipe"


class RetryableStatusError(Exception):
    """Raised for a status in :data:`RETRYABLE_STATUS` so tenacity retries the call."""

    def __init__(self, status_code: int) -> None:
        super().__init__(f"retryable HTTP status {status_code}")
        self.status_code = status_code


class CacheProtocol(Protocol):
    """The slice of the ``diskcache.Cache`` API the clients rely on."""

    def get(self, key: str, default: Any = None) -> Any: ...

    def set(self, key: str, value: Any, expire: float | None = None) -> Any: ...


def open_cache(directory: str | Path) -> CacheProtocol:
    """Open (creating if needed) a disk-backed cache under ``directory``."""
    cache: CacheProtocol = diskcache.Cache(str(directory))
    return cache


class HttpJsonClient:
    """A small JSON-over-HTTP engine with throttling, retries, and shared headers.

    Wraps an :class:`httpx.Client`, applying a minimum inter-request interval and
    retrying transient transport / 5xx / 429 failures with exponential backoff.
    """

    def __init__(
        self,
        *,
        http_client: httpx.Client | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        min_request_interval: float = 0.0,
        headers: Mapping[str, str] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        base_headers = {"User-Agent": _USER_AGENT}
        if headers:
            base_headers.update(headers)
        self._client = http_client if http_client is not None else httpx.Client(timeout=timeout)
        self._owns_client = http_client is None
        self._headers = base_headers
        self._min_request_interval = min_request_interval
        self._sleep = sleep
        self._last_request_at: float | None = None
        self._retrying = Retrying(
            stop=stop_after_attempt(max_attempts),
            wait=wait_exponential(multiplier=_BACKOFF_MULTIPLIER, max=_BACKOFF_MAX),
            retry=retry_if_exception_type((httpx.TransportError, RetryableStatusError)),
            sleep=sleep,
            reraise=True,
        )

    def _throttle(self) -> None:
        """Sleep just long enough to keep requests at least ``min_request_interval`` apart."""
        if self._min_request_interval <= 0:
            return
        if self._last_request_at is not None:
            remaining = self._min_request_interval - (time.monotonic() - self._last_request_at)
            if remaining > 0:
                self._sleep(remaining)
        self._last_request_at = time.monotonic()

    def get_json(self, url: str, *, params: Mapping[str, str] | None = None) -> tuple[int, Any]:
        """GET ``url`` and return ``(status_code, parsed_json_or_none)``.

        Retries transient failures; once retries are exhausted it raises the
        underlying ``httpx`` error or :class:`RetryableStatusError`. A non-2xx
        response yields ``(status_code, None)``; a 2xx body that is not valid JSON
        also yields ``(status_code, None)`` rather than raising.
        """
        result: tuple[int, Any] = self._retrying(self._fetch, url, params)
        return result

    def _fetch(self, url: str, params: Mapping[str, str] | None) -> tuple[int, Any]:
        self._throttle()
        response = self._client.get(url, params=dict(params or {}), headers=self._headers)
        if response.status_code in RETRYABLE_STATUS:
            raise RetryableStatusError(response.status_code)
        if response.is_success:
            try:
                return response.status_code, response.json()
            except ValueError:
                return response.status_code, None
        return response.status_code, None

    def close(self) -> None:
        """Close the underlying client if this instance created it."""
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "HttpJsonClient":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


__all__ = [
    "DEFAULT_MAX_ATTEMPTS",
    "DEFAULT_TIMEOUT",
    "RETRYABLE_STATUS",
    "CacheProtocol",
    "HttpJsonClient",
    "RetryableStatusError",
    "open_cache",
]
