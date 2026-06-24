"""Unit tests for wiring authenticated contexts into the ZAP scanner.

Drives ``ZapScanner.scan()`` against a fake ZAP client (no real daemon) to assert
that a target's ``auth`` block configures the context and switches the spider and
active scan to their ``*_as_user`` variants, that header auth uses a Replacer rule
with no ZAP user, and that an auth-setup failure degrades to an unauthenticated
scan rather than aborting the target.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from vulnpipe.core.config import Config, FormAuth, HeaderAuth, Scope, Target, ZapConfig
from vulnpipe.scanners import zap_scanner
from vulnpipe.scanners.zap_scanner import (
    ZapScanner,
    select_web_targets,
    select_web_targets_with_auth,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
URL = "https://app.lab.example.com"


def _load_alerts() -> list[dict[str, Any]]:
    data = json.loads((FIXTURES / "sample_zap_alerts.json").read_text(encoding="utf-8"))
    alerts = data["alerts"]
    assert isinstance(alerts, list)
    return alerts


class _Recorder:
    """Records every method call on a ZAP API component, with canned return values."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def __getattr__(self, name: str) -> Any:
        def method(*args: Any, **kwargs: Any) -> str:
            self.calls.append((name, args, kwargs))
            return {"new_user": "9", "new_context": "1", "status": "100"}.get(name, "OK")

        return method

    def named(self, name: str) -> list[tuple[str, tuple[Any, ...], dict[str, Any]]]:
        return [call for call in self.calls if call[0] == name]


class _FakeZap:
    """A ZAP client whose components record calls; ``core.alerts`` returns a fixture."""

    def __init__(self, *, apikey: str | None = None, proxies: Any = None) -> None:
        self.apikey = apikey
        self.proxies = proxies
        self.spider = _Recorder()
        self.ascan = _Recorder()
        self.context = _Recorder()
        self.authentication = _Recorder()
        self.sessionManagement = _Recorder()
        self.users = _Recorder()
        self.replacer = _Recorder()
        self.core = self

    def alerts(self, baseurl: Any = None, **_kwargs: Any) -> list[dict[str, Any]]:
        return _load_alerts()


def _patch(monkeypatch: pytest.MonkeyPatch) -> dict[str, _FakeZap]:
    created: dict[str, _FakeZap] = {}

    def ctor(apikey: str | None = None, proxies: Any = None) -> _FakeZap:
        zap = _FakeZap(apikey=apikey, proxies=proxies)
        created["zap"] = zap
        return zap

    monkeypatch.setattr(zap_scanner, "ZAPv2", ctor)
    return created


def _config(auth: Any) -> Config:
    return Config(
        scope=Scope(hosts=["*.lab.example.com"]),
        targets=[Target(urls=[URL], auth=auth)],
        zap=ZapConfig(),
    )


# --------------------------------------------------------------------------- #
# Target selection carries auth
# --------------------------------------------------------------------------- #
def test_select_with_auth_carries_target_auth() -> None:
    auth = FormAuth(login_url=f"{URL}/login", username_env="U", password_env="P")
    cfg = _config(auth)
    targets = select_web_targets_with_auth(cfg)
    assert len(targets) == 1
    assert targets[0].url == URL
    assert targets[0].auth is auth
    # The URL-only view still returns plain strings (unchanged contract).
    assert select_web_targets(cfg) == [URL]


def test_select_with_auth_dedupes_keeping_first_auth() -> None:
    first = FormAuth(login_url=f"{URL}/login", username_env="U", password_env="P")
    second = HeaderAuth(token_env="T")
    cfg = Config(
        scope=Scope(hosts=["*.lab.example.com"]),
        targets=[Target(urls=[URL], auth=first), Target(urls=[URL], auth=second)],
    )
    targets = select_web_targets_with_auth(cfg)
    assert len(targets) == 1
    assert targets[0].auth is first  # first occurrence wins


# --------------------------------------------------------------------------- #
# Authenticated scan flow
# --------------------------------------------------------------------------- #
def test_form_auth_scans_as_user(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("U", "alice")
    monkeypatch.setenv("P", "s3cr3t")
    created = _patch(monkeypatch)
    auth = FormAuth(
        login_url=f"{URL}/login",
        username_env="U",
        password_env="P",
        logged_in_indicator="Log out",
    )
    findings = ZapScanner(_config(auth)).scan()
    assert len(findings) == 5  # out-of-scope corp alert filtered

    zap = created["zap"]
    # The context was set up for authenticated scanning.
    assert zap.authentication.named("set_authentication_method")
    assert zap.users.named("new_user")
    assert zap.authentication.named("set_logged_in_indicator")
    # Spider and active scan run as the authenticated user.
    assert zap.spider.named("scan_as_user")
    assert zap.ascan.named("scan_as_user")
    assert zap.spider.named("scan") == []  # not the unauthenticated path


def test_header_auth_uses_replacer_without_user(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("T", "jwt-token")
    created = _patch(monkeypatch)
    findings = ZapScanner(_config(HeaderAuth(token_env="T"))).scan()
    assert len(findings) == 5

    zap = created["zap"]
    rule = zap.replacer.named("add_rule")
    assert rule and rule[0][2]["replacement"] == "Bearer jwt-token"
    assert zap.users.named("new_user") == []  # header auth needs no user
    # No user -> the normal (header-injected) spider/active-scan path is used.
    assert zap.spider.named("scan")
    assert zap.spider.named("scan_as_user") == []


def test_missing_credentials_degrade_to_unauthenticated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("U", raising=False)
    monkeypatch.delenv("P", raising=False)
    created = _patch(monkeypatch)
    auth = FormAuth(login_url=f"{URL}/login", username_env="U", password_env="P")
    # The missing credential must not abort the target; the scan proceeds unauthenticated.
    findings = ZapScanner(_config(auth)).scan()
    assert len(findings) == 5

    zap = created["zap"]
    assert zap.authentication.named("set_authentication_method") == []  # auth never applied
    assert zap.users.named("new_user") == []
    assert zap.spider.named("scan")  # fell back to the unauthenticated spider
    assert zap.spider.named("scan_as_user") == []


def test_unauthenticated_target_does_not_touch_auth_components(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created = _patch(monkeypatch)
    findings = ZapScanner(_config(None)).scan()
    assert len(findings) == 5

    zap = created["zap"]
    assert zap.authentication.calls == []
    assert zap.users.calls == []
    assert zap.replacer.calls == []
    assert zap.spider.named("scan")  # plain spider/active-scan path
