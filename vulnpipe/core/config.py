"""Configuration loading, schema validation, and the authorization/scope guards.

Responsibilities:

* Parse a YAML target file and substitute ``${ENV_VAR}`` references from the
  environment (``load_config``).
* Validate it against a strict pydantic schema (scope / targets / auth).
* Enforce the project's non-negotiable authorization rules: a scan may only run
  with an explicit acknowledgement *and* a non-empty scope allowlist, and every
  target must fall inside that allowlist (``ensure_authorized`` /
  ``ensure_target_in_scope``).

Secrets (credentials, API keys) are referenced by environment-variable *name*
and resolved at scan time via :func:`resolve_secret`; they are never stored in
the YAML or materialized into the in-memory config.
"""

import ipaddress
import os
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")
_ENV_REF_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-(.*?))?\}")


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #
class ConfigError(Exception):
    """Raised when configuration cannot be loaded or fails schema validation."""


class AuthorizationError(ConfigError):
    """Raised when a scan is attempted without explicit authorization/scope."""


class OutOfScopeError(ConfigError):
    """Raised when a target falls outside the configured scope allowlist."""


# --------------------------------------------------------------------------- #
# Schema helpers
# --------------------------------------------------------------------------- #
def _as_network(value: str) -> IPNetwork | None:
    """Parse ``value`` as an IP address or CIDR network, or return ``None``."""
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _subnet_of(target: IPNetwork, allowed: IPNetwork) -> bool:
    """Whether ``target`` is fully contained in ``allowed`` (same IP family only)."""
    if isinstance(target, ipaddress.IPv4Network) and isinstance(allowed, ipaddress.IPv4Network):
        return target.subnet_of(allowed)
    if isinstance(target, ipaddress.IPv6Network) and isinstance(allowed, ipaddress.IPv6Network):
        return target.subnet_of(allowed)
    return False


def _is_host_or_cidr(value: str) -> bool:
    return _as_network(value) is not None or bool(_HOSTNAME_RE.match(value))


def _validate_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"Invalid URL (expected http(s)://host...): {value!r}")
    return value


# --------------------------------------------------------------------------- #
# Authentication schema (discriminated on `type`)
# --------------------------------------------------------------------------- #
class _AuthBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    logged_in_indicator: str | None = None
    logged_out_indicator: str | None = None


class FormAuth(_AuthBase):
    """Form-based authentication context for ZAP."""

    type: Literal["form"] = "form"
    login_url: str
    username_field: str = "username"
    password_field: str = "password"
    username_env: str = Field(description="Env var name holding the username.")
    password_env: str = Field(description="Env var name holding the password.")
    extra_fields: dict[str, str] = Field(default_factory=dict)

    @field_validator("login_url")
    @classmethod
    def _check_login_url(cls, value: str) -> str:
        return _validate_url(value)


class HeaderAuth(_AuthBase):
    """Header / bearer-token (JWT) authentication context for ZAP."""

    type: Literal["header"] = "header"
    header_name: str = "Authorization"
    token_env: str = Field(description="Env var name holding the bearer/JWT token.")
    token_prefix: str = "Bearer "


class ScriptAuth(_AuthBase):
    """Script-based authentication context for ZAP."""

    type: Literal["script"] = "script"
    script_name: str
    script_engine: str = "Oracle Nashorn"
    parameters: dict[str, str] = Field(default_factory=dict)


AuthConfig = Annotated[FormAuth | HeaderAuth | ScriptAuth, Field(discriminator="type")]


# --------------------------------------------------------------------------- #
# Scope / target schema
# --------------------------------------------------------------------------- #
class Scope(BaseModel):
    """The authorization allowlist; nothing outside this may be scanned.

    ``hosts`` holds IPs, CIDRs, hostnames, or ``*.domain`` wildcards (network
    scope). ``urls`` holds full ``http(s)://host[/path]`` prefixes (web scope).
    """

    model_config = ConfigDict(extra="forbid")

    hosts: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)

    @field_validator("hosts")
    @classmethod
    def _check_hosts(cls, value: list[str]) -> list[str]:
        for entry in value:
            candidate = entry[2:] if entry.startswith("*.") else entry
            if not _is_host_or_cidr(candidate):
                raise ValueError(f"Invalid scope host entry: {entry!r}")
        return value

    @field_validator("urls")
    @classmethod
    def _check_urls(cls, value: list[str]) -> list[str]:
        return [_validate_url(url) for url in value]


class Target(BaseModel):
    """A scan target: a network host/CIDR, one or more web URLs, or both."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    host: str | None = None
    urls: list[str] = Field(default_factory=list)
    auth: AuthConfig | None = None

    @field_validator("host")
    @classmethod
    def _check_host(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip()
        if not candidate or not _is_host_or_cidr(candidate):
            raise ValueError(f"Invalid host / CIDR / hostname: {value!r}")
        return candidate

    @field_validator("urls")
    @classmethod
    def _check_urls(cls, value: list[str]) -> list[str]:
        return [_validate_url(url) for url in value]

    @model_validator(mode="after")
    def _require_host_or_urls(self) -> "Target":
        if self.host is None and not self.urls:
            raise ValueError("target must define at least one of 'host' or 'urls'")
        return self


# --------------------------------------------------------------------------- #
# Scanner / pipeline settings
# --------------------------------------------------------------------------- #
class NmapConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    binary: str = "nmap"
    timing_template: int = Field(default=4, ge=0, le=5)
    ports: str | None = None
    top_ports: int | None = Field(default=None, ge=1, le=65535)
    scripts: list[str] = Field(default_factory=lambda: ["vulners"])
    timeout_seconds: int = Field(default=1800, ge=1)
    extra_args: list[str] = Field(default_factory=list)


class ZapConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    api_url: str = "http://localhost:8080"
    api_key_env: str = "ZAP_API_KEY"
    spider_max_duration_minutes: int = Field(default=5, ge=0)
    active_scan_timeout_seconds: int = Field(default=3600, ge=1)
    max_concurrency: int = Field(default=1, ge=1)

    @field_validator("api_url")
    @classmethod
    def _check_api_url(cls, value: str) -> str:
        return _validate_url(value)


class EnrichmentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nvd_enabled: bool = True
    nvd_api_key_env: str = "NVD_API_KEY"
    epss_enabled: bool = True
    cache_dir: str = ".cache"


class RunConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_workers: int = Field(default=10, ge=1)


class Config(BaseModel):
    """Top-level pipeline configuration loaded from the YAML target file."""

    model_config = ConfigDict(extra="forbid")

    scope: Scope
    targets: list[Target] = Field(min_length=1)
    nmap: NmapConfig = Field(default_factory=NmapConfig)
    zap: ZapConfig = Field(default_factory=ZapConfig)
    enrichment: EnrichmentConfig = Field(default_factory=EnrichmentConfig)
    run: RunConfig = Field(default_factory=RunConfig)


# --------------------------------------------------------------------------- #
# Loading (YAML + environment)
# --------------------------------------------------------------------------- #
def _interpolate(value: str) -> str:
    """Substitute ``${VAR}`` / ``${VAR:-default}`` from the environment."""

    def replace(match: "re.Match[str]") -> str:
        name, default = match.group(1), match.group(2)
        if name in os.environ:
            return os.environ[name]
        if default is not None:
            return default
        raise ConfigError(f"Environment variable {name!r} referenced in config is not set")

    return _ENV_REF_RE.sub(replace, value)


def _interpolate_tree(node: Any) -> Any:
    if isinstance(node, dict):
        return {key: _interpolate_tree(val) for key, val in node.items()}
    if isinstance(node, list):
        return [_interpolate_tree(item) for item in node]
    if isinstance(node, str):
        return _interpolate(node)
    return node


def load_config(path: str | Path) -> Config:
    """Load, env-interpolate, and validate a YAML config file into a :class:`Config`."""
    config_path = Path(path)
    if not config_path.is_file():
        raise ConfigError(f"Config file not found: {config_path}")
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"Failed to parse YAML config {config_path}: {exc}") from exc
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError(f"Config root must be a mapping, got {type(raw).__name__}")
    interpolated = _interpolate_tree(raw)
    try:
        return Config.model_validate(interpolated)
    except ValidationError as exc:
        raise ConfigError(f"Invalid configuration in {config_path}:\n{exc}") from exc


def resolve_secret(env_name: str, *, required: bool = True) -> str | None:
    """Resolve a secret from the environment by variable name.

    Secrets never live in the config file; only their env-var name does. Raises
    :class:`ConfigError` if ``required`` and the variable is unset.
    """
    value = os.environ.get(env_name)
    if value is None and required:
        raise ConfigError(f"Required secret {env_name!r} is not set in the environment")
    return value


# --------------------------------------------------------------------------- #
# Authorization & scope enforcement (hard rules)
# --------------------------------------------------------------------------- #
def host_in_scope(host: str, allowed: Iterable[str]) -> bool:
    """Return whether ``host`` (IP, CIDR, or hostname) is covered by ``allowed``.

    IP/CIDR targets must be a subnet of (or equal to) an allowed network. A
    hostname matches an exact hostname entry, or a ``*.domain`` wildcard entry
    (which also matches the bare ``domain``).
    """
    allowed_entries = list(allowed)
    target_net = _as_network(host)

    if target_net is not None:
        for entry in allowed_entries:
            entry_net = _as_network(entry)
            if entry_net is not None and _subnet_of(target_net, entry_net):
                return True
        return False

    target_name = host.strip().lower().rstrip(".")
    for entry in allowed_entries:
        if _as_network(entry) is not None:
            continue
        candidate = entry.strip().lower().rstrip(".")
        if candidate.startswith("*."):
            base = candidate[2:]
            if target_name == base or target_name.endswith(f".{base}"):
                return True
        elif target_name == candidate:
            return True
    return False


def url_in_scope(url: str, scope: Scope) -> bool:
    """Return whether ``url`` is within scope.

    In scope if it matches a ``scope.urls`` prefix (on a path boundary), or if
    its hostname/IP is within ``scope.hosts``.
    """
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        return False
    normalized = url.rstrip("/")
    for allowed in scope.urls:
        base = allowed.rstrip("/")
        if normalized == base or normalized.startswith(f"{base}/"):
            return True
    return host_in_scope(parsed.hostname, scope.hosts)


def ensure_target_in_scope(target: Target, scope: Scope) -> None:
    """Raise :class:`OutOfScopeError` if any part of ``target`` is out of scope."""
    if target.host is not None and not host_in_scope(target.host, scope.hosts):
        raise OutOfScopeError(
            f"Network target {target.host!r} is not within the configured scope allowlist"
        )
    for url in target.urls:
        if not url_in_scope(url, scope):
            raise OutOfScopeError(
                f"Web target {url!r} is not within the configured scope allowlist"
            )


def ensure_config_in_scope(config: Config) -> None:
    """Validate that every target in ``config`` is within scope."""
    for target in config.targets:
        ensure_target_in_scope(target, config.scope)


def ensure_authorized(*, authorized: bool, scope: Scope) -> None:
    """Enforce the authorization precondition before any scan runs.

    Requires both an explicit acknowledgement (``--authorized``) and a non-empty
    scope allowlist. Raises :class:`AuthorizationError` otherwise.
    """
    if not authorized:
        raise AuthorizationError(
            "Refusing to scan: authorization not acknowledged (pass --authorized)"
        )
    if not scope.hosts and not scope.urls:
        raise AuthorizationError("Refusing to scan: the scope allowlist is empty")


__all__ = [
    "AuthConfig",
    "AuthorizationError",
    "Config",
    "ConfigError",
    "EnrichmentConfig",
    "FormAuth",
    "HeaderAuth",
    "NmapConfig",
    "OutOfScopeError",
    "RunConfig",
    "Scope",
    "ScriptAuth",
    "Target",
    "ZapConfig",
    "ensure_authorized",
    "ensure_config_in_scope",
    "ensure_target_in_scope",
    "host_in_scope",
    "load_config",
    "resolve_secret",
    "url_in_scope",
]
