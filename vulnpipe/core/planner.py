"""Dry-run scan planning: what *would* be scanned, without scanning anything.

Turns a validated :class:`~vulnpipe.core.config.Config` into a :class:`ScanPlan` --
the in-scope network targets, the declared web targets (with their auth scheme), any
targets that fall *outside* the scope allowlist, the enrichment sources that are
enabled, and the environment variables the run will need for secrets. This backs the
``vulnpipe validate`` command, which lets an operator confirm a config before
committing to an intrusive scan.

:func:`build_scan_plan` is a pure function (config in, plan out -- no filesystem, no
network, no environment access) and :func:`render_plan` renders it deterministically,
so both are trivially testable. Unlike the scanner target selectors, planning does
not *raise* on an out-of-scope target: it records it, so ``validate`` can report every
problem at once rather than failing on the first.
"""

from dataclasses import dataclass

from vulnpipe.core.config import AuthConfig, Config, host_in_scope, url_in_scope


@dataclass(frozen=True)
class PlannedWebTarget:
    """A declared web URL that is in scope, with its ZAP auth scheme (if any)."""

    url: str
    auth: str | None


@dataclass(frozen=True)
class ScanPlan:
    """The resolved plan for a config: what the scan would cover, and any problems."""

    scope_hosts: int
    scope_urls: int
    network_targets: tuple[str, ...]
    web_targets: tuple[PlannedWebTarget, ...]
    out_of_scope: tuple[str, ...]
    enrichment_sources: tuple[str, ...]
    secret_env_names: tuple[str, ...]
    nmap_enabled: bool
    zap_enabled: bool
    nuclei_enabled: bool
    sbom_count: int
    import_count: int

    @property
    def scope_is_empty(self) -> bool:
        """Whether the scope allowlist is empty (a scan would refuse to start)."""
        return self.scope_hosts == 0 and self.scope_urls == 0

    @property
    def is_valid(self) -> bool:
        """Whether the config would pass the authorization gate and is fully in scope."""
        return not self.out_of_scope and not self.scope_is_empty


def _auth_secret_names(auth: AuthConfig) -> list[str]:
    """The environment-variable names an auth config resolves its credentials from."""
    if auth.type == "form":
        return [auth.username_env, auth.password_env]
    if auth.type == "header":
        return [auth.token_env]
    return [name for name in (auth.username_env, auth.password_env) if name is not None]


def build_scan_plan(config: Config) -> ScanPlan:
    """Resolve ``config`` into a :class:`ScanPlan` (pure; no scanning, no I/O).

    Every declared target is scope-checked: an in-scope network host joins
    ``network_targets`` (de-duplicated) and an in-scope URL joins ``web_targets`` with
    its auth scheme, while anything out of scope is recorded in ``out_of_scope`` with a
    human-readable reason. Enrichment sources and the secret env-var names the run will
    need are collected for the operator to confirm.
    """
    network: dict[str, None] = {}
    web: list[PlannedWebTarget] = []
    out_of_scope: list[str] = []
    secrets: dict[str, None] = {}

    for target in config.targets:
        label = target.name or target.host or (target.urls[0] if target.urls else "?")
        if target.host is not None:
            if host_in_scope(target.host, config.scope.hosts):
                network.setdefault(target.host, None)
            else:
                out_of_scope.append(
                    f"network target {target.host!r} (in {label!r}) is out of scope"
                )
        for url in target.urls:
            if url_in_scope(url, config.scope):
                scheme = target.auth.type if target.auth is not None else None
                web.append(PlannedWebTarget(url=url, auth=scheme))
            else:
                out_of_scope.append(f"web target {url!r} (in {label!r}) is out of scope")
        if target.auth is not None:
            for name in _auth_secret_names(target.auth):
                secrets.setdefault(name, None)

    if config.zap.enabled and web:
        secrets.setdefault(config.zap.api_key_env, None)

    sources: list[str] = []
    if config.enrichment.nvd_enabled:
        sources.append("nvd")
    if config.enrichment.epss_enabled:
        sources.append("epss")
    if config.enrichment.kev_enabled:
        sources.append("kev")

    return ScanPlan(
        scope_hosts=len(config.scope.hosts),
        scope_urls=len(config.scope.urls),
        network_targets=tuple(network),
        web_targets=tuple(web),
        out_of_scope=tuple(out_of_scope),
        enrichment_sources=tuple(sources),
        secret_env_names=tuple(secrets),
        nmap_enabled=config.nmap.enabled,
        zap_enabled=config.zap.enabled,
        nuclei_enabled=config.nuclei.enabled,
        sbom_count=len(config.sbom),
        import_count=len(config.imports),
    )


def render_plan(plan: ScanPlan) -> str:
    """Render a :class:`ScanPlan` as a deterministic, human-readable summary."""
    lines: list[str] = ["Scan plan (dry run — nothing is scanned)", ""]
    lines.append(
        f"scope:        {plan.scope_hosts} host pattern(s), {plan.scope_urls} URL prefix(es)"
    )
    lines.append(f"nmap:         {'enabled' if plan.nmap_enabled else 'disabled'}")
    lines.append(f"zap:          {'enabled' if plan.zap_enabled else 'disabled'}")
    lines.append(f"nuclei:       {'enabled' if plan.nuclei_enabled else 'disabled'}")
    lines.append(f"enrichment:   {', '.join(plan.enrichment_sources) or 'none'}")
    lines.append(f"sbom:         {plan.sbom_count} file(s)")
    lines.append(f"imports:      {plan.import_count} report(s)")

    lines.append("")
    lines.append(f"network targets ({len(plan.network_targets)}):")
    for host in plan.network_targets:
        lines.append(f"  - {host}")

    lines.append(f"web targets ({len(plan.web_targets)}):")
    for target in plan.web_targets:
        suffix = f"  (auth: {target.auth})" if target.auth else ""
        lines.append(f"  - {target.url}{suffix}")

    if plan.secret_env_names:
        lines.append("")
        lines.append("required environment variables:")
        for name in plan.secret_env_names:
            lines.append(f"  - {name}")

    lines.append("")
    if plan.scope_is_empty:
        lines.append("INVALID: the scope allowlist is empty; a scan would refuse to start.")
    if plan.out_of_scope:
        lines.append(f"INVALID: {len(plan.out_of_scope)} target(s) out of scope:")
        for reason in plan.out_of_scope:
            lines.append(f"  - {reason}")
    if plan.is_valid:
        lines.append("OK: every target is in scope and the scope allowlist is non-empty.")
    return "\n".join(lines) + "\n"


__all__ = [
    "PlannedWebTarget",
    "ScanPlan",
    "build_scan_plan",
    "render_plan",
]
