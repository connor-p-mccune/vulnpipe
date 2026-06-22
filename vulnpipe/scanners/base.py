"""Scanner abstraction.

Each scanner subclasses :class:`BaseScanner` and implements ``scan()``, returning
normalized :class:`~vulnpipe.core.models.Finding` objects. Nothing downstream
knows which tool produced a finding except via ``Finding.source``. Register new
scanners through :mod:`vulnpipe.scanners.registry` rather than special-casing them
in the orchestrator.
"""

from abc import ABC, abstractmethod
from typing import ClassVar

from vulnpipe.core.config import Config
from vulnpipe.core.models import Finding


class BaseScanner(ABC):
    """Common interface for all scanners."""

    #: Stable name used as the registry key and as ``Finding.source``.
    name: ClassVar[str]

    def __init__(self, config: Config) -> None:
        self.config = config

    @abstractmethod
    def scan(self) -> list[Finding]:
        """Scan the in-scope targets and return normalized findings."""
        raise NotImplementedError
