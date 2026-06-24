"""Unit tests for configuration loading, validation, and env handling."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnpipe.core.config import (
    AssetRule,
    AuthorizationError,
    Config,
    ConfigError,
    FormAuth,
    HeaderAuth,
    PrioritizationConfig,
    ScriptAuth,
    Target,
    ensure_authorized,
    ensure_config_in_scope,
    load_config,
    resolve_secret,
)
from vulnpipe.core.models import AssetCriticality

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_CONFIG = REPO_ROOT / "configs" / "targets.example.yaml"

MINIMAL_YAML = """
scope:
  hosts: ["10.0.0.0/24"]
targets:
  - name: net
    host: "10.0.0.0/24"
"""


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "cfg.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_load_minimal_config(tmp_path: Path) -> None:
    cfg = load_config(_write(tmp_path, MINIMAL_YAML))
    assert isinstance(cfg, Config)
    assert cfg.scope.hosts == ["10.0.0.0/24"]
    assert cfg.targets[0].host == "10.0.0.0/24"
    # defaults populated
    assert cfg.nmap.timing_template == 4
    assert cfg.zap.max_concurrency == 1
    assert cfg.run.max_workers == 10


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(tmp_path / "nope.yaml")


def test_missing_scope_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, "targets:\n  - host: 10.0.0.1\n"))


def test_empty_targets_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, "scope:\n  hosts: ['10.0.0.0/24']\ntargets: []\n"))


def test_invalid_url_target_raises(tmp_path: Path) -> None:
    text = "scope:\n  urls: ['https://app.example.com']\ntargets:\n  - urls: ['ftp://nope']\n"
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, text))


def test_unknown_key_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, MINIMAL_YAML + "bogus: true\n"))


def test_target_requires_host_or_urls() -> None:
    with pytest.raises(ValidationError):
        Target(name="empty")


def test_env_interpolation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ZAP_URL", "http://zap.internal:8080")
    text = (
        "scope:\n  hosts: ['10.0.0.0/24']\n"
        "targets:\n  - host: '10.0.0.1'\n"
        "zap:\n  api_url: '${ZAP_URL}'\n"
    )
    cfg = load_config(_write(tmp_path, text))
    assert cfg.zap.api_url == "http://zap.internal:8080"


def test_env_interpolation_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MISSING_VAR", raising=False)
    text = (
        "scope:\n  hosts: ['10.0.0.0/24']\n"
        "targets:\n  - host: '10.0.0.1'\n"
        "zap:\n  api_url: '${MISSING_VAR:-http://localhost:8080}'\n"
    )
    cfg = load_config(_write(tmp_path, text))
    assert cfg.zap.api_url == "http://localhost:8080"


def test_env_interpolation_missing_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MISSING_VAR", raising=False)
    text = "scope:\n  hosts: ['10.0.0.0/24']\ntargets:\n  - host: '${MISSING_VAR}'\n"
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, text))


def test_resolve_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_SECRET", "s3cr3t")
    assert resolve_secret("MY_SECRET") == "s3cr3t"
    monkeypatch.delenv("MY_SECRET", raising=False)
    assert resolve_secret("MY_SECRET", required=False) is None
    with pytest.raises(ConfigError):
        resolve_secret("MY_SECRET")


def test_auth_discriminated_union() -> None:
    form = Target(
        host="10.0.0.1",
        auth={
            "type": "form",
            "login_url": "https://app.example.com/login",
            "username_env": "U",
            "password_env": "P",
        },
    )
    assert isinstance(form.auth, FormAuth)

    header = Target(host="10.0.0.1", auth={"type": "header", "token_env": "T"})
    assert isinstance(header.auth, HeaderAuth)

    script = Target(host="10.0.0.1", auth={"type": "script", "script_name": "login.js"})
    assert isinstance(script.auth, ScriptAuth)


def test_example_config_loads_and_is_internally_consistent() -> None:
    cfg = load_config(EXAMPLE_CONFIG)
    # every target is inside the example's own scope
    ensure_config_in_scope(cfg)
    # authorization gate behaves as documented
    ensure_authorized(authorized=True, scope=cfg.scope)
    with pytest.raises(AuthorizationError):
        ensure_authorized(authorized=False, scope=cfg.scope)


def test_prioritization_defaults_to_medium() -> None:
    cfg = PrioritizationConfig()
    assert cfg.default_criticality is AssetCriticality.MEDIUM
    assert cfg.criticality_for("10.0.0.99") is AssetCriticality.MEDIUM


def test_prioritization_first_matching_rule_wins() -> None:
    cfg = PrioritizationConfig(
        default_criticality=AssetCriticality.LOW,
        assets=[
            AssetRule(host="10.0.0.10", criticality=AssetCriticality.CRITICAL),
            AssetRule(host="10.0.0.0/24", criticality=AssetCriticality.HIGH),
        ],
    )
    assert cfg.criticality_for("10.0.0.10") is AssetCriticality.CRITICAL  # exact rule first
    assert cfg.criticality_for("10.0.0.50") is AssetCriticality.HIGH  # falls through to the CIDR
    assert cfg.criticality_for("192.168.0.1") is AssetCriticality.LOW  # default


def test_prioritization_matches_wildcard_host() -> None:
    cfg = PrioritizationConfig(
        assets=[AssetRule(host="*.lab.example.com", criticality=AssetCriticality.HIGH)]
    )
    assert cfg.criticality_for("api.lab.example.com") is AssetCriticality.HIGH
    assert cfg.criticality_for("lab.example.com") is AssetCriticality.HIGH
    assert cfg.criticality_for("other.example.com") is AssetCriticality.MEDIUM


def test_asset_rule_rejects_invalid_host() -> None:
    with pytest.raises(ValidationError):
        AssetRule(host="not a host!", criticality=AssetCriticality.HIGH)


def test_example_config_defines_prioritization() -> None:
    cfg = load_config(EXAMPLE_CONFIG)
    assert cfg.prioritization.criticality_for("10.0.0.10") is AssetCriticality.CRITICAL
    assert cfg.prioritization.criticality_for("10.0.0.50") is AssetCriticality.HIGH
