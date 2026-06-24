"""Unit tests for ZAP authentication contexts.

Two layers are covered with no live ZAP: building a resolved context from config
(secrets pulled from the environment) and applying it to a fake ZAP client that
records the API calls.
"""

from typing import Any

import pytest

from vulnpipe.auth.auth_contexts import (
    USER_NAME,
    FormAuthContext,
    HeaderAuthContext,
    ScriptAuthContext,
    apply_auth_context,
    build_auth_context,
)
from vulnpipe.core.config import ConfigError, FormAuth, HeaderAuth, ScriptAuth


class _Recorder:
    """Records every method call made on a ZAP API component."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def __getattr__(self, name: str) -> Any:
        def method(*args: Any, **kwargs: Any) -> str:
            self.calls.append((name, args, kwargs))
            return "7" if name == "new_user" else "OK"

        return method

    def named(self, name: str) -> list[tuple[str, tuple[Any, ...], dict[str, Any]]]:
        return [call for call in self.calls if call[0] == name]


class _FakeZap:
    """A ZAP client exposing only the components the auth layer touches."""

    def __init__(self) -> None:
        self.authentication = _Recorder()
        self.sessionManagement = _Recorder()
        self.users = _Recorder()
        self.replacer = _Recorder()


# --------------------------------------------------------------------------- #
# build_auth_context: form
# --------------------------------------------------------------------------- #
def test_build_form_resolves_credentials_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_USER", "alice")
    monkeypatch.setenv("APP_PASS", "s3cr3t!")
    auth = FormAuth(
        login_url="https://app.example.com/login",
        username_field="email",
        password_field="password",
        username_env="APP_USER",
        password_env="APP_PASS",
        extra_fields={"csrf": "x y"},
        logged_in_indicator="Log out",
        logged_out_indicator="Login",
    )
    ctx = build_auth_context(auth)
    assert isinstance(ctx, FormAuthContext)
    assert ctx.kind == "form"
    assert ctx.username == "alice" and ctx.password == "s3cr3t!"
    assert ctx.login_url == "https://app.example.com/login"
    # ZAP placeholders for credentials; extra fields URL-encoded literally.
    assert ctx.login_request_data == "email={%username%}&password={%password%}&csrf=x%20y"
    assert ctx.logged_in_indicator == "Log out"
    assert ctx.logged_out_indicator == "Login"


def test_build_form_missing_secret_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APP_USER", raising=False)
    monkeypatch.setenv("APP_PASS", "s3cr3t!")
    auth = FormAuth(
        login_url="https://app.example.com/login",
        username_env="APP_USER",
        password_env="APP_PASS",
    )
    with pytest.raises(ConfigError, match="APP_USER"):
        build_auth_context(auth)


# --------------------------------------------------------------------------- #
# build_auth_context: header / bearer
# --------------------------------------------------------------------------- #
def test_build_header_composes_bearer_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("API_TOKEN", "abc.def.ghi")
    ctx = build_auth_context(HeaderAuth(token_env="API_TOKEN"))
    assert isinstance(ctx, HeaderAuthContext)
    assert ctx.header_name == "Authorization"
    assert ctx.header_value == "Bearer abc.def.ghi"


def test_build_header_custom_name_and_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("API_TOKEN", "tok")
    ctx = build_auth_context(
        HeaderAuth(header_name="X-Api-Key", token_env="API_TOKEN", token_prefix="")
    )
    assert isinstance(ctx, HeaderAuthContext)
    assert ctx.header_name == "X-Api-Key"
    assert ctx.header_value == "tok"


def test_build_header_missing_token_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    with pytest.raises(ConfigError, match="API_TOKEN"):
        build_auth_context(HeaderAuth(token_env="API_TOKEN"))


# --------------------------------------------------------------------------- #
# build_auth_context: script
# --------------------------------------------------------------------------- #
def test_build_script_builds_params_and_optional_user(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SVC_USER", "svc")
    monkeypatch.setenv("SVC_PASS", "pw")
    auth = ScriptAuth(
        script_name="jwt-login.js",
        parameters={"loginUrl": "https://api.example.com/auth"},
        username_env="SVC_USER",
        password_env="SVC_PASS",
    )
    ctx = build_auth_context(auth)
    assert isinstance(ctx, ScriptAuthContext)
    assert ctx.auth_params == "scriptName=jwt-login.js&loginUrl=https%3A//api.example.com/auth"
    assert ctx.username == "svc" and ctx.password == "pw"


def test_build_script_without_credentials_has_no_user() -> None:
    ctx = build_auth_context(ScriptAuth(script_name="login.js"))
    assert isinstance(ctx, ScriptAuthContext)
    assert ctx.username is None and ctx.password is None
    assert ctx.auth_params == "scriptName=login.js"


# --------------------------------------------------------------------------- #
# apply_auth_context: form
# --------------------------------------------------------------------------- #
def test_apply_form_configures_method_session_and_user() -> None:
    zap = _FakeZap()
    ctx = FormAuthContext(
        login_url="https://app.example.com/login",
        login_request_data="email={%username%}&password={%password%}",
        username="alice",
        password="s3cr3t!",
        logged_in_indicator="Log out",
        logged_out_indicator="Login",
    )
    user_id = apply_auth_context(zap, "1", ctx)
    assert user_id == "7"

    method_call = zap.authentication.named("set_authentication_method")[0]
    assert method_call[1][0] == "1"  # context id
    assert method_call[1][1] == "formBasedAuthentication"
    assert method_call[1][2].startswith("loginUrl=")
    assert "loginRequestData=" in method_call[1][2]

    assert zap.authentication.named("set_logged_in_indicator")[0][1] == ("1", "Log out")
    assert zap.authentication.named("set_logged_out_indicator")[0][1] == ("1", "Login")
    assert zap.sessionManagement.named("set_session_management_method")

    # The user is created with env-resolved credentials and enabled.
    assert zap.users.named("new_user")[0][1] == ("1", USER_NAME)
    creds = zap.users.named("set_authentication_credentials")[0][1]
    assert creds == ("1", "7", "username=alice&password=s3cr3t%21")
    assert zap.users.named("set_user_enabled")[0][1] == ("1", "7", "true")


def test_apply_form_without_indicators_skips_them() -> None:
    zap = _FakeZap()
    ctx = FormAuthContext(
        login_url="https://app.example.com/login",
        login_request_data="email={%username%}&password={%password%}",
        username="a",
        password="b",
    )
    apply_auth_context(zap, "1", ctx)
    assert zap.authentication.named("set_logged_in_indicator") == []
    assert zap.authentication.named("set_logged_out_indicator") == []


# --------------------------------------------------------------------------- #
# apply_auth_context: header / bearer
# --------------------------------------------------------------------------- #
def test_apply_header_adds_replacer_rule_and_no_user() -> None:
    zap = _FakeZap()
    ctx = HeaderAuthContext(header_name="Authorization", header_value="Bearer tok")
    user_id = apply_auth_context(zap, "2", ctx)
    assert user_id is None  # header auth needs no ZAP user

    rule = zap.replacer.named("add_rule")[0]
    assert rule[2]["matchtype"] == "REQ_HEADER"
    assert rule[2]["matchstring"] == "Authorization"
    assert rule[2]["replacement"] == "Bearer tok"
    assert zap.users.calls == []  # no user created


# --------------------------------------------------------------------------- #
# apply_auth_context: script
# --------------------------------------------------------------------------- #
def test_apply_script_sets_method_and_creates_user_when_credentialed() -> None:
    zap = _FakeZap()
    ctx = ScriptAuthContext(
        script_name="login.js",
        script_engine="Oracle Nashorn",
        auth_params="scriptName=login.js",
        username="svc",
        password="pw",
    )
    user_id = apply_auth_context(zap, "3", ctx)
    assert user_id == "7"
    method_call = zap.authentication.named("set_authentication_method")[0]
    assert method_call[1][1] == "scriptBasedAuthentication"
    assert method_call[1][2] == "scriptName=login.js"
    assert zap.users.named("new_user")


def test_apply_script_without_credentials_creates_no_user() -> None:
    zap = _FakeZap()
    ctx = ScriptAuthContext(
        script_name="login.js",
        script_engine="Oracle Nashorn",
        auth_params="scriptName=login.js",
    )
    assert apply_auth_context(zap, "3", ctx) is None
    assert zap.users.calls == []
