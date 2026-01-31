"""Scanner orchestrator."""

import fnmatch
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from hackmenot.core.cache import FileCache
from hackmenot.core.config import Config
from hackmenot.core.ignores import IgnoreHandler
from hackmenot.core.models import Finding, ScanResult, Severity
from hackmenot.parsers.golang import GoParser
from hackmenot.parsers.javascript import JavaScriptParser
from hackmenot.parsers.python import PythonParser
from hackmenot.parsers.terraform import TerraformParser
from hackmenot.rules.engine import RulesEngine
from hackmenot.rules.registry import RuleRegistry


class Scanner:
    """Main scanner that orchestrates parsing and rule checking."""

    SUPPORTED_EXTENSIONS = {".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".go", ".tf", ".tfvars"}
    JS_EXTENSIONS = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}
    GO_EXTENSIONS = {".go"}
    TERRAFORM_EXTENSIONS = {".tf", ".tfvars"}
    DEFAULT_WORKERS = min(32, (os.cpu_count() or 1) + 4)
    SKIP_DIRS = {
        "node_modules",
        "__pycache__",
        ".git",
        ".hg",
        ".svn",
        "venv",
        ".venv",
        "env",
        ".env",
        ".tox",
        ".nox",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "dist",
        "build",
        ".eggs",
        "vendor",
        "third_party",
        ".terraform",
    }

    def __init__(
        self, cache: FileCache | None = None, config: Config | None = None
    ) -> None:
        self.parser = PythonParser()
        self.js_parser = JavaScriptParser()
        self.go_parser = GoParser()
        self.tf_parser = TerraformParser()
        self.engine = RulesEngine()
        self.cache = cache
        self.config = config or Config()
        self._load_rules()

    def _load_rules(self) -> None:
        """Load all built-in rules, respecting disabled rules from config."""
        registry = RuleRegistry()
        registry.load_all()
        disabled = set(self.config.rules_disable)
        for rule in registry.get_all_rules():
            if rule.id not in disabled:
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
        """Collect all scannable files from paths, respecting path excludes."""
        files: list[Path] = []

        for path in paths:
            if path.is_file():
                if path.suffix in self.SUPPORTED_EXTENSIONS:
                    files.append(path)
            elif path.is_dir():
                for root, dirs, filenames in os.walk(path):
                    # Prune SKIP_DIRS in-place to prevent descending
                    dirs[:] = [
                        d for d in dirs
                        if d not in self.SKIP_DIRS and not d.endswith(".egg-info")
                    ]

                    root_path = Path(root)
                    for filename in filenames:
                        file_path = root_path / filename
                        if file_path.suffix in self.SUPPORTED_EXTENSIONS:
                            files.append(file_path)

        # Filter out excluded paths
        if self.config.paths_exclude:
            files = [f for f in files if not self._is_excluded(f, paths)]

        return sorted(set(files))

    def _is_excluded(self, file_path: Path, scan_roots: list[Path]) -> bool:
        """Check if a file path matches any exclusion pattern.

        Args:
            file_path: The file path to check.
            scan_roots: The root paths being scanned.

        Returns:
            True if the path should be excluded.
        """
        # Try to get relative path from any scan root
        for root in scan_roots:
            try:
                relative = file_path.relative_to(root)
                relative_str = str(relative)
                for pattern in self.config.paths_exclude:
                    if fnmatch.fnmatch(relative_str, pattern):
                        return True
            except ValueError:
                # file_path is not relative to this root
                continue
        return False

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

    def _detect_language(self, file_path: Path) -> str:
        """Detect the language of a file based on its extension.

        Args:
            file_path: The file path to check.

        Returns:
            "python", "javascript", "go", or "terraform" based on the file extension.
        """
        if file_path.suffix in self.JS_EXTENSIONS:
            return "javascript"
        if file_path.suffix in self.GO_EXTENSIONS:
            return "go"
        if file_path.suffix in self.TERRAFORM_EXTENSIONS:
            return "terraform"
        return "python"

    def _scan_file(self, file_path: Path) -> list[Finding]:
        """Scan a single file, respecting inline ignore comments."""
        # Read source content for ignore parsing
        source = file_path.read_text()

        # Parse ignore comments
        ignore_handler = IgnoreHandler()
        ignores = ignore_handler.parse(source)

        # Check for file-level ignore
        if ignore_handler.is_file_ignored():
            return []

        # Detect language and use appropriate parser
        language = self._detect_language(file_path)

        if language == "javascript":
            # Parse JavaScript/TypeScript file
            parse_result = self.js_parser.parse_file(file_path)
            if parse_result.has_error:
                return []
            return self.engine.check(parse_result, file_path, ignores=ignores)
        elif language == "go":
            # Parse Go file
            parse_result = self.go_parser.parse_file(file_path)
            if parse_result.has_error:
                return []
            return self.engine.check(parse_result, file_path, ignores=ignores)
        elif language == "terraform":
            # Parse Terraform file
            parse_result = self.tf_parser.parse_file(file_path)
            if parse_result.has_error:
                return []
            return self.engine.check(parse_result, file_path, ignores=ignores)
        else:
            # Parse Python file
            parse_result = self.parser.parse_file(file_path)
            if parse_result.has_error:
                return []
            return self.engine.check(parse_result, file_path, ignores=ignores)
