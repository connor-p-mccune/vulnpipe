"""Reporter abstraction: render findings into a serialized report."""

from abc import ABC, abstractmethod
from typing import ClassVar

from vulnpipe.core.models import Finding


class BaseReporter(ABC):
    """Common interface for all reporters (JSON, HTML, SARIF)."""

    #: Stable name / format identifier for this reporter.
    name: ClassVar[str]

    @abstractmethod
    def render(self, findings: list[Finding]) -> str:
        """Render ``findings`` into a serialized report string."""
        raise NotImplementedError
