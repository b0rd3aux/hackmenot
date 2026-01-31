"""Core module for hackmenot."""

from hackmenot.core.cache import FileCache
from hackmenot.core.config import Config, ConfigLoader
from hackmenot.core.ignores import IgnoreHandler
from hackmenot.core.models import Finding, Rule, ScanResult, Severity

# Scanner is imported lazily to avoid circular imports with rules module


def __getattr__(name: str):
    """Lazy import for Scanner to avoid circular imports."""
    if name == "Scanner":
        from hackmenot.core.scanner import Scanner

        return Scanner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "Config",
    "ConfigLoader",
    "FileCache",
    "Finding",
    "IgnoreHandler",
    "Rule",
    "ScanResult",
    "Scanner",
    "Severity",
]
