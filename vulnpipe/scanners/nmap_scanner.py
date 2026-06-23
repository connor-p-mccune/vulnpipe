"""Nmap scanner integration (network layer).

This module drives the ``nmap`` binary and turns its XML output into normalized
:class:`~vulnpipe.core.models.Finding` objects. It is split into small pieces:

* :func:`select_network_targets` resolves the in-scope network targets from the
  configuration, enforcing the scope allowlist *before* any scan runs.
* :func:`build_nmap_command` assembles the argument list (always a list, never a
  shell string) used to invoke ``nmap``.

The XML parser and the :class:`BaseScanner` implementation build on these.
"""

from collections.abc import Sequence

from vulnpipe.core.config import Config, OutOfScopeError, host_in_scope

#: ``Finding.source`` and registry key for this scanner.
SOURCE = "nmap"


def select_network_targets(config: Config) -> list[str]:
    """Return the de-duplicated, in-scope network targets to hand to ``nmap``.

    Only :class:`~vulnpipe.core.config.Target` entries with a ``host`` (an IP,
    CIDR, or hostname) are network targets; URL-only targets belong to the web
    (ZAP) stage and are ignored here. Enforces the authorization scope as a hard
    rule: a configured host outside the allowlist raises
    :class:`~vulnpipe.core.config.OutOfScopeError` and no scan is attempted.
    """
    selected: list[str] = []
    seen: set[str] = set()
    for target in config.targets:
        if target.host is None:
            continue
        if not host_in_scope(target.host, config.scope.hosts):
            raise OutOfScopeError(
                f"Network target {target.host!r} is not within the configured scope allowlist"
            )
        if target.host not in seen:
            seen.add(target.host)
            selected.append(target.host)
    return selected


def build_nmap_command(config: Config, targets: Sequence[str]) -> list[str]:
    """Build the ``nmap`` argument list for ``targets``.

    Emits XML to stdout (``-oX -``) and enables service/version detection
    (``-sV``) so product/version data is available for both reporting and the
    vulners CPE matching. Timing, port selection, and NSE scripts come from
    :class:`~vulnpipe.core.config.NmapConfig`. Targets are passed as discrete
    arguments (nmap handles CIDR ranges and host lists natively); nothing is
    ever interpolated into a shell string.
    """
    cfg = config.nmap
    command = [cfg.binary, "-oX", "-", "-sV", f"-T{cfg.timing_template}"]
    if cfg.ports:
        command += ["-p", cfg.ports]
    elif cfg.top_ports is not None:
        command += ["--top-ports", str(cfg.top_ports)]
    if cfg.scripts:
        command += ["--script", ",".join(cfg.scripts)]
    command += list(cfg.extra_args)
    command += list(targets)
    return command


__all__ = [
    "SOURCE",
    "build_nmap_command",
    "select_network_targets",
]
