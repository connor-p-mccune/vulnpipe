"""Unit tests for the authorization scope checks (the core hard rule)."""

import pytest

from vulnpipe.core.config import (
    AuthorizationError,
    OutOfScopeError,
    Scope,
    Target,
    ensure_authorized,
    ensure_target_in_scope,
    host_in_scope,
    url_in_scope,
)


@pytest.mark.parametrize(
    ("host", "allowed", "expected"),
    [
        ("10.0.0.5", ["10.0.0.0/24"], True),
        ("10.0.1.5", ["10.0.0.0/24"], False),
        ("10.0.0.0/25", ["10.0.0.0/24"], True),  # subnet of allowed network
        ("10.0.0.0/24", ["10.0.0.0/25"], False),  # broader than allowed network
        ("192.168.1.1", ["10.0.0.0/8", "192.168.0.0/16"], True),
        ("2001:db8::1", ["2001:db8::/32"], True),
        ("10.0.0.5", ["2001:db8::/32"], False),  # mixed families do not match
        ("app.example.com", ["*.example.com"], True),
        ("example.com", ["*.example.com"], True),  # wildcard matches bare domain
        ("evil.com", ["*.example.com"], False),
        ("app.example.com", ["example.com"], False),  # exact entry is not a wildcard
        ("example.com", ["example.com"], True),
        ("app.example.com", ["10.0.0.0/24"], False),  # name vs network
    ],
)
def test_host_in_scope(host: str, allowed: list[str], expected: bool) -> None:
    assert host_in_scope(host, allowed) is expected


@pytest.mark.parametrize(
    ("url", "scope", "expected"),
    [
        ("https://app.example.com/login", Scope(urls=["https://app.example.com"]), True),
        ("https://app.example.com", Scope(urls=["https://app.example.com"]), True),
        ("https://app.example.com.evil.com/x", Scope(urls=["https://app.example.com"]), False),
        ("https://10.0.0.5/admin", Scope(hosts=["10.0.0.0/24"]), True),
        ("https://10.9.9.9/", Scope(hosts=["10.0.0.0/24"]), False),
        ("not-a-url", Scope(hosts=["10.0.0.0/24"]), False),
    ],
)
def test_url_in_scope(url: str, scope: Scope, expected: bool) -> None:
    assert url_in_scope(url, scope) is expected


def test_ensure_target_in_scope_passes() -> None:
    scope = Scope(hosts=["10.0.0.0/24"], urls=["https://app.example.com"])
    target = Target(host="10.0.0.10", urls=["https://app.example.com/api"])
    ensure_target_in_scope(target, scope)  # must not raise


def test_ensure_target_in_scope_rejects_host() -> None:
    scope = Scope(hosts=["10.0.0.0/24"])
    with pytest.raises(OutOfScopeError):
        ensure_target_in_scope(Target(host="192.168.0.1"), scope)


def test_ensure_target_in_scope_rejects_url() -> None:
    scope = Scope(hosts=["10.0.0.0/24"], urls=["https://app.example.com"])
    with pytest.raises(OutOfScopeError):
        ensure_target_in_scope(Target(host="10.0.0.5", urls=["https://evil.com"]), scope)


def test_ensure_authorized_requires_flag() -> None:
    scope = Scope(hosts=["10.0.0.0/24"])
    with pytest.raises(AuthorizationError):
        ensure_authorized(authorized=False, scope=scope)
    ensure_authorized(authorized=True, scope=scope)  # must not raise


def test_ensure_authorized_rejects_empty_scope() -> None:
    with pytest.raises(AuthorizationError):
        ensure_authorized(authorized=True, scope=Scope())
