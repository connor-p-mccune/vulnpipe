"""Unit tests for the shared enrichment HTTP engine (all HTTP mocked with respx)."""

from typing import Any

import httpx
import pytest
import respx

from vulnpipe.enrichment._http import (
    RETRYABLE_STATUS,
    HttpJsonClient,
    RetryableStatusError,
    open_cache,
)

URL = "https://api.example.test/data"


def _client(**kwargs: Any) -> HttpJsonClient:
    """A client whose retry/throttle never sleeps for real (test-fast)."""
    kwargs.setdefault("sleep", lambda _seconds: None)
    kwargs.setdefault("min_request_interval", 0.0)
    return HttpJsonClient(**kwargs)


# --------------------------------------------------------------------------- #
# get_json: status / body handling
# --------------------------------------------------------------------------- #
@respx.mock
def test_get_json_success() -> None:
    respx.get(URL).mock(return_value=httpx.Response(200, json={"ok": 1}))
    with _client() as client:
        status, data = client.get_json(URL, params={"q": "x"})
    assert status == 200
    assert data == {"ok": 1}


@respx.mock
def test_get_json_404_returns_none_body() -> None:
    respx.get(URL).mock(return_value=httpx.Response(404))
    status, data = _client().get_json(URL)
    assert status == 404
    assert data is None


@respx.mock
def test_get_json_client_error_returns_none_body() -> None:
    respx.get(URL).mock(return_value=httpx.Response(403))
    status, data = _client().get_json(URL)
    assert status == 403
    assert data is None


@respx.mock
def test_get_json_invalid_json_on_200_returns_none() -> None:
    respx.get(URL).mock(return_value=httpx.Response(200, text="not json"))
    status, data = _client().get_json(URL)
    assert status == 200
    assert data is None


@respx.mock
def test_get_json_sends_shared_and_custom_headers() -> None:
    route = respx.get(URL).mock(return_value=httpx.Response(200, json={}))
    _client(headers={"apiKey": "secret"}).get_json(URL)
    request = route.calls.last.request
    assert request.headers["user-agent"] == "vulnpipe"
    assert request.headers["apikey"] == "secret"


# --------------------------------------------------------------------------- #
# post_json (same engine, JSON-body POST)
# --------------------------------------------------------------------------- #
@respx.mock
def test_post_json_success_sends_body_and_headers() -> None:
    route = respx.post(URL).mock(return_value=httpx.Response(200, json={"vulns": []}))
    with _client() as client:
        status, data = client.post_json(URL, json_body={"package": {"purl": "pkg:pypi/x"}})
    assert status == 200
    assert data == {"vulns": []}
    request = route.calls.last.request
    assert request.headers["user-agent"] == "vulnpipe"
    assert b'"pkg:pypi/x"' in request.content


@respx.mock
def test_post_json_404_returns_none_body() -> None:
    respx.post(URL).mock(return_value=httpx.Response(404))
    status, data = _client().post_json(URL, json_body={})
    assert status == 404
    assert data is None


@respx.mock
def test_post_json_retries_retryable_status() -> None:
    route = respx.post(URL)
    route.side_effect = [httpx.Response(503), httpx.Response(200, json={"ok": 1})]
    status, data = _client().post_json(URL, json_body={})
    assert status == 200
    assert data == {"ok": 1}
    assert route.call_count == 2


@respx.mock
def test_post_json_exhausted_retries_raise() -> None:
    respx.post(URL).mock(return_value=httpx.Response(503))
    with pytest.raises(RetryableStatusError):
        _client(max_attempts=2).post_json(URL, json_body={})


# --------------------------------------------------------------------------- #
# Retry behavior
# --------------------------------------------------------------------------- #
@respx.mock
def test_retries_retryable_status_then_succeeds() -> None:
    slept: list[float] = []
    route = respx.get(URL)
    route.side_effect = [
        httpx.Response(503),
        httpx.Response(503),
        httpx.Response(200, json={"ok": True}),
    ]
    client = _client(max_attempts=4, sleep=slept.append)
    status, data = client.get_json(URL)
    assert status == 200
    assert data == {"ok": True}
    assert route.call_count == 3
    assert len(slept) == 2  # backed off twice before the success


@respx.mock
def test_exhausted_retryable_status_raises() -> None:
    slept: list[float] = []
    respx.get(URL).mock(return_value=httpx.Response(503))
    client = _client(max_attempts=3, sleep=slept.append)
    with pytest.raises(RetryableStatusError) as excinfo:
        client.get_json(URL)
    assert excinfo.value.status_code == 503
    assert len(slept) == 2  # max_attempts - 1 backoffs


@respx.mock
def test_retries_transport_error_then_succeeds() -> None:
    slept: list[float] = []
    route = respx.get(URL)
    route.side_effect = [httpx.ConnectError("boom"), httpx.Response(200, json={"ok": 1})]
    status, data = _client(max_attempts=3, sleep=slept.append).get_json(URL)
    assert status == 200 and data == {"ok": 1}
    assert len(slept) == 1


@respx.mock
def test_exhausted_transport_error_reraises() -> None:
    slept: list[float] = []
    respx.get(URL).mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(httpx.ConnectError):
        _client(max_attempts=2, sleep=slept.append).get_json(URL)
    assert len(slept) == 1


def test_retryable_status_set() -> None:
    assert 429 in RETRYABLE_STATUS
    assert {500, 502, 503, 504} <= RETRYABLE_STATUS
    assert 404 not in RETRYABLE_STATUS


# --------------------------------------------------------------------------- #
# Throttle
# --------------------------------------------------------------------------- #
def test_throttle_spaces_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []
    ticks = iter([1000.0, 1002.0, 1005.0])
    monkeypatch.setattr("vulnpipe.enrichment._http.time.monotonic", lambda: next(ticks))
    client = HttpJsonClient(min_request_interval=5.0, sleep=slept.append)
    client._throttle()  # first call: nothing to wait for
    client._throttle()  # 2s elapsed of a 5s interval -> sleep 3s
    assert slept == [3.0]


def test_throttle_noop_when_interval_zero() -> None:
    slept: list[float] = []
    client = HttpJsonClient(min_request_interval=0.0, sleep=slept.append)
    client._throttle()
    client._throttle()
    assert slept == []


# --------------------------------------------------------------------------- #
# Client lifecycle
# --------------------------------------------------------------------------- #
def test_owns_client_closed_on_close() -> None:
    client = _client()
    client.close()
    assert client._client.is_closed


def test_provided_client_not_closed() -> None:
    provided = httpx.Client()
    with HttpJsonClient(http_client=provided):
        pass
    assert not provided.is_closed
    provided.close()


# --------------------------------------------------------------------------- #
# Cache
# --------------------------------------------------------------------------- #
def test_open_cache_roundtrip(tmp_path: Any) -> None:
    cache = open_cache(tmp_path / "cache")
    assert cache.get("missing") is None
    cache.set("k", {"v": 1}, expire=100)
    assert cache.get("k") == {"v": 1}
