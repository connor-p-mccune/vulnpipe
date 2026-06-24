"""ZAP authentication contexts.

Authenticated scanning is the single biggest false-positive reducer: without it ZAP
spends the scan logged out and reports spurious 401/redirect findings. This module
turns the auth block of a target (:data:`~vulnpipe.core.config.AuthConfig`) into the
configuration ZAP needs, for all three supported schemes:

* **form** -- ZAP's ``formBasedAuthentication`` with a login URL and a request-data
  template, plus a user whose credentials come from the environment;
* **header / JWT bearer** -- a ZAP Replacer rule that injects an ``Authorization``
  (or custom) header carrying a bearer token on every request;
* **script** -- ZAP's ``scriptBasedAuthentication`` against a script already loaded
  into the daemon, optionally with an env-resolved user.

The module is split in two, mirroring the rest of the codebase:

* :func:`build_auth_context` is **pure** -- given an :data:`AuthConfig` (and the
  environment) it returns a resolved, frozen context object. It resolves secrets via
  :func:`~vulnpipe.core.config.resolve_secret`, so a missing credential is a clear
  error and no credential is ever read from the config file. This is the part that
  "builds correctly from config" with no live ZAP.
* :func:`apply_auth_context` performs the side effects -- the ZAP API calls that
  attach the resolved context (auth method, session management, logged-in/out
  indicators, and the user) to a ZAP context. It is exercised against a fake ZAP
  client in the unit tests.

Resolved credentials live only on the transient context object during a scan and are
never logged, serialized, or written back into the config model.
"""

import logging
from dataclasses import dataclass
from typing import Any, ClassVar, assert_never
from urllib.parse import quote

from vulnpipe.core.config import (
    AuthConfig,
    ConfigError,
    FormAuth,
    HeaderAuth,
    ScriptAuth,
    resolve_secret,
)
from vulnpipe.core.logging import get_logger, log_event

_log = get_logger(__name__)

#: Name of the ZAP user vulnpipe creates for credentialed auth schemes.
USER_NAME = "vulnpipe-user"

# ZAP method/session identifiers.
_FORM_METHOD = "formBasedAuthentication"
_SCRIPT_METHOD = "scriptBasedAuthentication"
_SESSION_METHOD = "cookieBasedSessionManagement"


# --------------------------------------------------------------------------- #
# Resolved context objects (pure data, secrets resolved from the environment)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class FormAuthContext:
    """A resolved form-based auth context ready to apply to a ZAP context."""

    kind: ClassVar[str] = "form"
    login_url: str
    #: ZAP ``loginRequestData`` with ``{%username%}`` / ``{%password%}`` placeholders.
    login_request_data: str
    username: str
    password: str
    logged_in_indicator: str | None = None
    logged_out_indicator: str | None = None


@dataclass(frozen=True)
class HeaderAuthContext:
    """A resolved header/bearer-token context (applied as a ZAP Replacer rule)."""

    kind: ClassVar[str] = "header"
    header_name: str
    header_value: str
    logged_in_indicator: str | None = None
    logged_out_indicator: str | None = None


@dataclass(frozen=True)
class ScriptAuthContext:
    """A resolved script-based auth context for a script already loaded in ZAP."""

    kind: ClassVar[str] = "script"
    script_name: str
    script_engine: str
    #: ZAP auth-method config string (``scriptName=...&param=value...``).
    auth_params: str
    username: str | None = None
    password: str | None = None
    logged_in_indicator: str | None = None
    logged_out_indicator: str | None = None


ZapAuthContext = FormAuthContext | HeaderAuthContext | ScriptAuthContext


# --------------------------------------------------------------------------- #
# Pure construction from config
# --------------------------------------------------------------------------- #
def _require_secret(env_name: str) -> str:
    """Resolve a required credential from the environment, or raise :class:`ConfigError`."""
    secret = resolve_secret(env_name, required=False)
    if secret is None:
        raise ConfigError(f"Required auth credential {env_name!r} is not set in the environment")
    return secret


def _encode_pair(name: str, value: str) -> str:
    return f"{quote(name)}={quote(value)}"


def _form_login_request_data(auth: FormAuth) -> str:
    """Build ZAP's ``loginRequestData`` with credential placeholders and extra fields.

    The username/password fields use ZAP's ``{%username%}`` / ``{%password%}``
    placeholders (filled from the user's credentials at scan time); any
    ``extra_fields`` are appended as literal, URL-encoded form values.
    """
    parts = [
        f"{quote(auth.username_field)}={{%username%}}",
        f"{quote(auth.password_field)}={{%password%}}",
    ]
    parts.extend(_encode_pair(key, value) for key, value in auth.extra_fields.items())
    return "&".join(parts)


def _script_auth_params(auth: ScriptAuth) -> str:
    """Build the ZAP script-auth method config: ``scriptName=...`` plus parameters."""
    parts = [f"scriptName={quote(auth.script_name)}"]
    parts.extend(_encode_pair(key, value) for key, value in auth.parameters.items())
    return "&".join(parts)


def _build_form(auth: FormAuth) -> FormAuthContext:
    return FormAuthContext(
        login_url=auth.login_url,
        login_request_data=_form_login_request_data(auth),
        username=_require_secret(auth.username_env),
        password=_require_secret(auth.password_env),
        logged_in_indicator=auth.logged_in_indicator,
        logged_out_indicator=auth.logged_out_indicator,
    )


def _build_header(auth: HeaderAuth) -> HeaderAuthContext:
    token = _require_secret(auth.token_env)
    return HeaderAuthContext(
        header_name=auth.header_name,
        header_value=f"{auth.token_prefix}{token}",
        logged_in_indicator=auth.logged_in_indicator,
        logged_out_indicator=auth.logged_out_indicator,
    )


def _build_script(auth: ScriptAuth) -> ScriptAuthContext:
    username = _require_secret(auth.username_env) if auth.username_env else None
    password = _require_secret(auth.password_env) if auth.password_env else None
    return ScriptAuthContext(
        script_name=auth.script_name,
        script_engine=auth.script_engine,
        auth_params=_script_auth_params(auth),
        username=username,
        password=password,
        logged_in_indicator=auth.logged_in_indicator,
        logged_out_indicator=auth.logged_out_indicator,
    )


def build_auth_context(auth: AuthConfig) -> ZapAuthContext:
    """Resolve an :data:`AuthConfig` into a ready-to-apply ZAP auth context.

    Pure apart from reading the environment for credentials: no ZAP, no network.
    Raises :class:`~vulnpipe.core.config.ConfigError` if a referenced credential
    environment variable is unset.
    """
    if isinstance(auth, FormAuth):
        return _build_form(auth)
    if isinstance(auth, HeaderAuth):
        return _build_header(auth)
    if isinstance(auth, ScriptAuth):
        return _build_script(auth)
    assert_never(auth)


# --------------------------------------------------------------------------- #
# Applying a context to a live ZAP daemon (side effects)
# --------------------------------------------------------------------------- #
def _set_indicators(client: Any, context_id: str, ctx: ZapAuthContext) -> None:
    """Set the logged-in / logged-out indicators on the context when configured."""
    if ctx.logged_in_indicator is not None:
        client.authentication.set_logged_in_indicator(context_id, ctx.logged_in_indicator)
    if ctx.logged_out_indicator is not None:
        client.authentication.set_logged_out_indicator(context_id, ctx.logged_out_indicator)


def _create_user(client: Any, context_id: str, username: str, password: str) -> str:
    """Create and enable a ZAP user with the given credentials; return its id."""
    user_id = str(client.users.new_user(context_id, USER_NAME))
    credentials = f"{_encode_pair('username', username)}&{_encode_pair('password', password)}"
    client.users.set_authentication_credentials(context_id, user_id, credentials)
    client.users.set_user_enabled(context_id, user_id, "true")
    return user_id


def _apply_form(client: Any, context_id: str, ctx: FormAuthContext) -> str:
    config = (
        f"{_encode_pair('loginUrl', ctx.login_url)}"
        f"&{_encode_pair('loginRequestData', ctx.login_request_data)}"
    )
    client.authentication.set_authentication_method(context_id, _FORM_METHOD, config)
    _set_indicators(client, context_id, ctx)
    client.sessionManagement.set_session_management_method(context_id, _SESSION_METHOD, None)
    return _create_user(client, context_id, ctx.username, ctx.password)


def _apply_header(client: Any, context_id: str, ctx: HeaderAuthContext) -> None:
    """Inject the bearer/JWT header on every request via a ZAP Replacer rule."""
    client.replacer.add_rule(
        description=f"vulnpipe-auth-{context_id}",
        enabled="true",
        matchtype="REQ_HEADER",
        matchregex="false",
        matchstring=ctx.header_name,
        replacement=ctx.header_value,
    )
    _set_indicators(client, context_id, ctx)


def _apply_script(client: Any, context_id: str, ctx: ScriptAuthContext) -> str | None:
    client.authentication.set_authentication_method(context_id, _SCRIPT_METHOD, ctx.auth_params)
    _set_indicators(client, context_id, ctx)
    client.sessionManagement.set_session_management_method(context_id, _SESSION_METHOD, None)
    if ctx.username is not None and ctx.password is not None:
        return _create_user(client, context_id, ctx.username, ctx.password)
    return None


def apply_auth_context(client: Any, context_id: str, ctx: ZapAuthContext) -> str | None:
    """Attach a resolved auth context to a ZAP context; return the user id if any.

    Configures the authentication method, session management, and logged-in/out
    indicators on the ZAP context, creating an enabled ZAP user for the credentialed
    schemes (form, and script when credentials are supplied). Header/bearer auth
    needs no user -- the token is injected globally via a Replacer rule -- so it
    returns ``None``. Credential values are passed to ZAP but never logged.
    """
    log_event(_log, logging.INFO, "configuring zap auth context", kind=ctx.kind)
    if isinstance(ctx, FormAuthContext):
        return _apply_form(client, context_id, ctx)
    if isinstance(ctx, HeaderAuthContext):
        _apply_header(client, context_id, ctx)
        return None
    if isinstance(ctx, ScriptAuthContext):
        return _apply_script(client, context_id, ctx)
    assert_never(ctx)


__all__ = [
    "USER_NAME",
    "FormAuthContext",
    "HeaderAuthContext",
    "ScriptAuthContext",
    "ZapAuthContext",
    "apply_auth_context",
    "build_auth_context",
]
