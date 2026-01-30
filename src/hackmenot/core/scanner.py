"""Scanner orchestrator."""

import time
from pathlib import Path

from hackmenot.core.models import Finding, ScanResult, Severity
from hackmenot.parsers.python import PythonParser
from hackmenot.rules.engine import RulesEngine
from hackmenot.rules.registry import RuleRegistry


class Scanner:
    """Main scanner that orchestrates parsing and rule checking."""

    SUPPORTED_EXTENSIONS = {".py"}

    def __init__(self) -> None:
        self.parser = PythonParser()
        self.engine = RulesEngine()
        self._load_rules()

    def _load_rules(self) -> None:
        """Load all built-in rules."""
        registry = RuleRegistry()
        registry.load_all()
        for rule in registry.get_all_rules():
            self.engine.register_rule(rule)

    def scan(
        self,
        paths: list[Path],
        min_severity: Severity = Severity.LOW,
    ) -> ScanResult:
        """Scan paths for security vulnerabilities."""
        start_time = time.time()

        files = self._collect_files(paths)
        findings: list[Finding] = []
        errors: list[str] = []

        for file_path in files:
            try:
                file_findings = self._scan_file(file_path)
                # Filter by severity
                file_findings = [f for f in file_findings if f.severity >= min_severity]
                findings.extend(file_findings)
            except Exception as e:
                errors.append(f"{file_path}: {e}")

        elapsed_ms = (time.time() - start_time) * 1000

        return ScanResult(
            files_scanned=len(files),
            findings=findings,
            scan_time_ms=elapsed_ms,
            errors=errors,
        )

    def _collect_files(self, paths: list[Path]) -> list[Path]:
        """Collect all scannable files from paths."""
        files: list[Path] = []

        for path in paths:
            if path.is_file():
                if path.suffix in self.SUPPORTED_EXTENSIONS:
                    files.append(path)
            elif path.is_dir():
                for ext in self.SUPPORTED_EXTENSIONS:
                    files.extend(path.rglob(f"*{ext}"))

        return sorted(set(files))

    def _scan_file(self, file_path: Path) -> list[Finding]:
        """Scan a single file."""
        parse_result = self.parser.parse_file(file_path)

        if parse_result.has_error:
            return []

        return self.engine.check(parse_result, file_path)
