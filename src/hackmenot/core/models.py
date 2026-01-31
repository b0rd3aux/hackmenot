"""Core data models for hackmenot."""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Severity levels for findings, ordered for comparison."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name.lower()

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Create Severity from string (case-insensitive)."""
        return cls[value.upper()]


@dataclass(frozen=True)
class FixConfig:
    """Configuration for automatic fixes."""

    template: str = ""  # Suggestion text for the user
    pattern: str = ""  # Pattern to match vulnerable code
    replacement: str = ""  # Replacement with placeholders


@dataclass(frozen=True)
class Finding:
    """A security finding in scanned code."""

    rule_id: str
    rule_name: str
    severity: Severity
    message: str
    file_path: str
    line_number: int
    column: int
    code_snippet: str
    fix_suggestion: str
    education: str
    context_before: list[str] = field(default_factory=list)
    context_after: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Rule:
    """A security rule definition."""

    id: str
    name: str
    severity: Severity
    category: str
    languages: list[str]
    description: str
    message: str
    pattern: dict[str, Any]
    fix: FixConfig = field(default_factory=FixConfig)
    education: str = ""
    references: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Result of a scan operation."""

    files_scanned: int
    findings: list[Finding]
    scan_time_ms: float
    errors: list[str] = field(default_factory=list)

    def summary_by_severity(self) -> dict[Severity, int]:
        """Count findings by severity level."""
        counts = {s: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    @property
    def has_findings(self) -> bool:
        """Check if there are any findings."""
        return len(self.findings) > 0

    def findings_at_or_above(self, min_severity: Severity) -> list[Finding]:
        """Get findings at or above a minimum severity."""
        return [f for f in self.findings if f.severity >= min_severity]
