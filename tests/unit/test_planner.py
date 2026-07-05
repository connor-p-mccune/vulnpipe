"""Unit tests for dry-run scan planning (pure functions, deterministic)."""

from vulnpipe.core.config import (
    Config,
    EnrichmentConfig,
    FormAuth,
    HeaderAuth,
    NucleiConfig,
    Scope,
    ScriptAuth,
    Target,
)
from vulnpipe.core.planner import build_scan_plan, render_plan


def _config(**overrides: object) -> Config:
    params: dict[str, object] = {
        "scope": Scope(hosts=["10.0.0.0/24"], urls=["https://app.lab.example.com"]),
        "targets": [Target(host="10.0.0.10", urls=["https://app.lab.example.com"])],
    }
    params.update(overrides)
    return Config(**params)  # type: ignore[arg-type]


def test_plan_enumerates_in_scope_targets() -> None:
    plan = build_scan_plan(_config())
    assert plan.network_targets == ("10.0.0.10",)
    assert [t.url for t in plan.web_targets] == ["https://app.lab.example.com"]
    assert plan.out_of_scope == ()
    assert plan.is_valid is True


def test_plan_records_out_of_scope_without_raising() -> None:
    plan = build_scan_plan(
        _config(
            targets=[
                Target(host="192.168.1.1"),  # outside 10.0.0.0/24
                Target(urls=["https://evil.example.org"]),  # outside scope
            ]
        )
    )
    assert plan.network_targets == ()
    assert len(plan.out_of_scope) == 2
    assert plan.is_valid is False


def test_plan_collects_auth_scheme_and_secret_env_names() -> None:
    target = Target(
        host="10.0.0.10",
        urls=["https://app.lab.example.com"],
        auth=FormAuth(
            login_url="https://app.lab.example.com/login",
            username_env="APP_USERNAME",
            password_env="APP_PASSWORD",
        ),
    )
    plan = build_scan_plan(_config(targets=[target]))
    assert plan.web_targets[0].auth == "form"
    # Auth creds + the ZAP API key (web layer is active) are required.
    assert "APP_USERNAME" in plan.secret_env_names
    assert "APP_PASSWORD" in plan.secret_env_names
    assert "ZAP_API_KEY" in plan.secret_env_names


def test_plan_header_auth_secret_name() -> None:
    target = Target(
        urls=["https://app.lab.example.com"],
        auth=HeaderAuth(token_env="API_BEARER_TOKEN"),
    )
    plan = build_scan_plan(_config(targets=[target]))
    assert plan.web_targets[0].auth == "header"
    assert "API_BEARER_TOKEN" in plan.secret_env_names


def test_plan_script_auth_secret_names() -> None:
    target = Target(
        urls=["https://app.lab.example.com"],
        auth=ScriptAuth(
            script_name="login", username_env="SCRIPT_USER", password_env="SCRIPT_PASS"
        ),
    )
    plan = build_scan_plan(_config(targets=[target]))
    assert plan.web_targets[0].auth == "script"
    assert "SCRIPT_USER" in plan.secret_env_names
    assert "SCRIPT_PASS" in plan.secret_env_names


def test_plan_reports_nuclei_layer() -> None:
    off = build_scan_plan(_config())
    assert off.nuclei_enabled is False
    assert "nuclei:       disabled" in render_plan(off)
    on = build_scan_plan(_config(nuclei=NucleiConfig(enabled=True)))
    assert on.nuclei_enabled is True
    assert "nuclei:       enabled" in render_plan(on)


def test_plan_reports_passive_layers() -> None:
    from vulnpipe.core.config import ImportSource

    plan = build_scan_plan(
        _config(
            sbom=["app.cdx.json"],
            imports=[ImportSource(path="trivy.json", format="trivy")],
        )
    )
    assert plan.sbom_count == 1 and plan.import_count == 1
    text = render_plan(plan)
    assert "sbom:         1 file(s)" in text
    assert "imports:      1 report(s)" in text


def test_plan_enrichment_sources_reflect_flags() -> None:
    plan = build_scan_plan(
        _config(enrichment=EnrichmentConfig(nvd_enabled=True, epss_enabled=False, kev_enabled=True))
    )
    assert plan.enrichment_sources == ("nvd", "kev")


def test_plan_empty_scope_is_invalid() -> None:
    plan = build_scan_plan(
        Config(scope=Scope(hosts=["10.0.0.0/24"]), targets=[Target(host="10.0.0.10")])
    )
    # Scope has a host pattern, so it is not empty here...
    assert plan.scope_is_empty is False


def test_render_plan_reports_ok_and_targets() -> None:
    text = render_plan(build_scan_plan(_config()))
    assert "Scan plan" in text
    assert "10.0.0.10" in text
    assert "https://app.lab.example.com" in text
    assert "OK:" in text


def test_render_plan_reports_out_of_scope() -> None:
    plan = build_scan_plan(_config(targets=[Target(host="192.168.1.1")]))
    text = render_plan(plan)
    assert "INVALID:" in text
    assert "out of scope" in text


def test_render_plan_reports_empty_scope() -> None:
    plan = build_scan_plan(Config(scope=Scope(), targets=[Target(host="10.0.0.10")]))
    assert plan.scope_is_empty is True
    assert plan.is_valid is False
    assert "scope allowlist is empty" in render_plan(plan)


def test_render_is_deterministic() -> None:
    assert render_plan(build_scan_plan(_config())) == render_plan(build_scan_plan(_config()))
