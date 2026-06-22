"""Scanner registry.

Scanners register here (typically via the :func:`register` decorator) so the
orchestrator can discover them by name without importing each one directly.
"""

from vulnpipe.scanners.base import BaseScanner

_REGISTRY: dict[str, type[BaseScanner]] = {}


def register(scanner_cls: type[BaseScanner]) -> type[BaseScanner]:
    """Register a scanner class under its ``name``. Usable as a class decorator."""
    _REGISTRY[scanner_cls.name] = scanner_cls
    return scanner_cls


def get_scanner(name: str) -> type[BaseScanner]:
    """Return the scanner class registered under ``name``."""
    try:
        return _REGISTRY[name]
    except KeyError as exc:
        raise KeyError(f"No scanner registered under {name!r}") from exc


def available_scanners() -> list[str]:
    """Return the sorted names of all registered scanners."""
    return sorted(_REGISTRY)
