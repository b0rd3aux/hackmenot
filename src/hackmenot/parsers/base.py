"""Base parser interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class FunctionInfo:
    """Information about a function definition."""

    name: str
    line_number: int
    column: int
    decorators: list[str] = field(default_factory=list)
    args: list[str] = field(default_factory=list)
    body_start: int = 0
    body_end: int = 0


@dataclass
class ClassInfo:
    """Information about a class definition."""

    name: str
    line_number: int
    column: int
    bases: list[str] = field(default_factory=list)
    methods: list[FunctionInfo] = field(default_factory=list)


@dataclass
class FStringInfo:
    """Information about an f-string."""

    value: str
    line_number: int
    column: int
    variables: list[str] = field(default_factory=list)


@dataclass
class ParseResult:
    """Result of parsing a file."""

    file_path: Path
    has_error: bool = False
    error_message: str | None = None
    _functions: list[FunctionInfo] = field(default_factory=list)
    _classes: list[ClassInfo] = field(default_factory=list)
    _fstrings: list[FStringInfo] = field(default_factory=list)
    _raw_ast: Any = None

    def get_functions(self) -> list[FunctionInfo]:
        """Get all function definitions."""
        return self._functions

    def get_classes(self) -> list[ClassInfo]:
        """Get all class definitions."""
        return self._classes

    def get_fstrings(self) -> list[FStringInfo]:
        """Get all f-strings."""
        return self._fstrings


class BaseParser(ABC):
    """Abstract base class for language parsers."""

    @abstractmethod
    def parse_file(self, file_path: Path) -> ParseResult:
        """Parse a file and return structured result."""
        pass

    @abstractmethod
    def parse_string(self, source: str, filename: str = "<string>") -> ParseResult:
        """Parse source code string and return structured result."""
        pass
