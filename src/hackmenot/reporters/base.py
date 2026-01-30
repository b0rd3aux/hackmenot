"""Base reporter interface."""

from abc import ABC, abstractmethod

from hackmenot.core.models import ScanResult


class BaseReporter(ABC):
    """Abstract base class for result reporters."""

    @abstractmethod
    def render(self, result: ScanResult) -> None:
        """Render scan results."""
        pass
