"""Scanner orchestrator."""

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from hackmenot.core.cache import FileCache
from hackmenot.core.models import Finding, ScanResult, Severity
from hackmenot.parsers.python import PythonParser
from hackmenot.rules.engine import RulesEngine
from hackmenot.rules.registry import RuleRegistry


class Scanner:
    """Main scanner that orchestrates parsing and rule checking."""

    SUPPORTED_EXTENSIONS = {".py"}
    DEFAULT_WORKERS = min(32, (os.cpu_count() or 1) + 4)

    def __init__(self, cache: FileCache | None = None) -> None:
        self.parser = PythonParser()
        self.engine = RulesEngine()
        self.cache = cache
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
        use_cache: bool = True,
        parallel: bool = False,
        max_workers: int | None = None,
    ) -> ScanResult:
        """Scan paths for security vulnerabilities.

        Args:
            paths: List of file or directory paths to scan.
            min_severity: Minimum severity level to include in results.
            use_cache: Whether to use cached results when available.
            parallel: Whether to scan files in parallel using ThreadPoolExecutor.
            max_workers: Maximum number of worker threads (defaults to DEFAULT_WORKERS).

        Returns:
            ScanResult containing findings, file count, timing, and errors.
        """
        start_time = time.time()

        files = self._collect_files(paths)
        findings: list[Finding] = []
        errors: list[str] = []

        if parallel and len(files) > 1:
            findings, errors = self._scan_parallel(
                files, use_cache, min_severity, max_workers
            )
        else:
            for file_path in files:
                try:
                    file_findings = self._get_findings_for_file(file_path, use_cache)
                    # Filter by severity
                    file_findings = [
                        f for f in file_findings if f.severity >= min_severity
                    ]
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

    def _scan_parallel(
        self,
        files: list[Path],
        use_cache: bool,
        min_severity: Severity,
        max_workers: int | None,
    ) -> tuple[list[Finding], list[str]]:
        """Scan files in parallel using ThreadPoolExecutor.

        Args:
            files: List of files to scan.
            use_cache: Whether to use cached results.
            min_severity: Minimum severity level to include.
            max_workers: Maximum number of worker threads.

        Returns:
            Tuple of (findings list, errors list).
        """
        findings: list[Finding] = []
        errors: list[str] = []
        workers = max_workers or self.DEFAULT_WORKERS

        with ThreadPoolExecutor(max_workers=workers) as executor:
            # Submit all file scanning tasks
            future_to_file = {
                executor.submit(self._get_findings_for_file, file_path, use_cache): file_path
                for file_path in files
            }

            # Collect results as they complete
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    file_findings = future.result()
                    # Filter by severity
                    file_findings = [
                        f for f in file_findings if f.severity >= min_severity
                    ]
                    findings.extend(file_findings)
                except Exception as e:
                    errors.append(f"{file_path}: {e}")

        return findings, errors

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

    def _get_findings_for_file(
        self, file_path: Path, use_cache: bool
    ) -> list[Finding]:
        """Get findings for a file, using cache if available."""
        if use_cache and self.cache is not None:
            cached = self.cache.get(file_path)
            if cached is not None:
                return cached

        findings = self._scan_file(file_path)

        if use_cache and self.cache is not None:
            self.cache.store(file_path, findings)

        return findings

    def _scan_file(self, file_path: Path) -> list[Finding]:
        """Scan a single file."""
        parse_result = self.parser.parse_file(file_path)

        if parse_result.has_error:
            return []

        return self.engine.check(parse_result, file_path)
