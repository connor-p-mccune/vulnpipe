"""Third-party plugin discovery via Python package entry points.

vulnpipe's scanner and reporter registries are open: an installed package can
advertise additional integrations under the ``vulnpipe.scanners`` and
``vulnpipe.reporters`` entry-point groups, and :func:`load_plugins` registers them
at CLI startup -- no changes to vulnpipe itself. A plugin package declares, e.g.::

    [project.entry-points."vulnpipe.scanners"]
    nikto = "vulnpipe_nikto.scanner:NiktoScanner"

    [project.entry-points."vulnpipe.reporters"]
    xlsx = "vulnpipe_xlsx.reporter:XlsxReporter"

The loaded object must be a concrete :class:`~vulnpipe.scanners.base.BaseScanner`
or :class:`~vulnpipe.reporting.base.BaseReporter` subclass with a non-empty
``name``; anything else is rejected. Discovery is defensive and deterministic:

* a broken plugin (import error, wrong type, missing ``name``) degrades to a
  logged warning -- it can never take down the pipeline;
* entry points are processed in sorted order, so registration order is stable;
* a plugin may not shadow an already-registered name: built-ins are registered
  first and always win, and the collision is warned about, never silent;
* loading is idempotent -- a name that is already registered with the same class
  is skipped quietly, so repeated calls are safe.
"""

import logging
from dataclasses import dataclass
from importlib.metadata import EntryPoint, entry_points
from typing import Any

import vulnpipe.scanners  # noqa: F401  (register built-in scanners before plugins)
from vulnpipe.core.logging import get_logger, log_event
from vulnpipe.reporting import available_formats, get_reporter, register_reporter
from vulnpipe.reporting.base import BaseReporter
from vulnpipe.scanners.base import BaseScanner
from vulnpipe.scanners.registry import available_scanners, get_scanner, register

#: Entry-point group a package uses to advertise additional scanners.
SCANNER_GROUP = "vulnpipe.scanners"
#: Entry-point group a package uses to advertise additional report formats.
REPORTER_GROUP = "vulnpipe.reporters"

_log = get_logger(__name__)


@dataclass(frozen=True)
class LoadedPlugin:
    """A successfully registered third-party plugin (for listing/diagnostics)."""

    kind: str  # "scanner" | "reporter"
    name: str  # registry name (Finding.source / report format)
    entry_point: str  # "package.module:ClassName" provenance

    @property
    def label(self) -> str:
        """A one-line human-readable description."""
        return f"{self.kind} {self.name!r} from {self.entry_point}"


#: Every plugin registered so far in this process (see :func:`loaded_plugins`).
_LOADED: list[LoadedPlugin] = []


def _sorted_entry_points(group: str) -> list[EntryPoint]:
    """The group's entry points in name order, so registration is deterministic."""
    return sorted(entry_points(group=group), key=lambda ep: ep.name)


def _load_class(ep: EntryPoint, base: type[Any]) -> tuple[type[Any], str]:
    """Resolve ``ep`` to a concrete ``base`` subclass and its registry name.

    Raises ``TypeError`` (or whatever the import raises) for anything that is not
    a usable plugin class; the caller turns that into a warning.
    """
    obj = ep.load()
    if not isinstance(obj, type) or not issubclass(obj, base) or obj is base:
        raise TypeError(f"{ep.value!r} is not a {base.__name__} subclass")
    name = getattr(obj, "name", None)
    if not isinstance(name, str) or not name:
        raise TypeError(f"{ep.value!r} does not define a non-empty `name`")
    return obj, name


def load_plugins() -> tuple[LoadedPlugin, ...]:
    """Discover and register scanner/reporter plugins from installed packages.

    Returns the plugins *newly* registered by this call. Failures and name
    collisions are logged warnings, never exceptions (see the module docstring).
    """
    new: list[LoadedPlugin] = []

    for ep in _sorted_entry_points(SCANNER_GROUP):
        try:
            scanner_cls, name = _load_class(ep, BaseScanner)
        except Exception as exc:  # a broken plugin must never take down the pipeline
            log_event(
                _log,
                logging.WARNING,
                "failed to load scanner plugin",
                entry_point=ep.value,
                error=str(exc),
            )
            continue
        if name in available_scanners():
            if get_scanner(name) is not scanner_cls:
                log_event(
                    _log,
                    logging.WARNING,
                    "scanner name already registered; refusing to override",
                    name=name,
                    entry_point=ep.value,
                )
            continue
        register(scanner_cls)
        new.append(LoadedPlugin(kind="scanner", name=name, entry_point=ep.value))
        log_event(_log, logging.INFO, "loaded scanner plugin", name=name, entry_point=ep.value)

    for ep in _sorted_entry_points(REPORTER_GROUP):
        try:
            reporter_cls, name = _load_class(ep, BaseReporter)
        except Exception as exc:  # a broken plugin must never take down the pipeline
            log_event(
                _log,
                logging.WARNING,
                "failed to load reporter plugin",
                entry_point=ep.value,
                error=str(exc),
            )
            continue
        if name in available_formats():
            if type(get_reporter(name)) is not reporter_cls:
                log_event(
                    _log,
                    logging.WARNING,
                    "report format already registered; refusing to override",
                    name=name,
                    entry_point=ep.value,
                )
            continue
        register_reporter(reporter_cls)
        new.append(LoadedPlugin(kind="reporter", name=name, entry_point=ep.value))
        log_event(_log, logging.INFO, "loaded reporter plugin", name=name, entry_point=ep.value)

    _LOADED.extend(new)
    return tuple(new)


def loaded_plugins() -> tuple[LoadedPlugin, ...]:
    """Every plugin registered in this process so far, in registration order."""
    return tuple(_LOADED)


__all__ = [
    "REPORTER_GROUP",
    "SCANNER_GROUP",
    "LoadedPlugin",
    "load_plugins",
    "loaded_plugins",
]
