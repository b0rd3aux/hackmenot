"""Parallel scanning implementation using multiprocessing."""

from __future__ import annotations

import multiprocessing
import queue
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hackmenot.core.constants import (
    DEFAULT_WORKERS,
    GO_EXTENSIONS,
    JAVA_EXTENSIONS,
    JS_EXTENSIONS,
    PYTHON_EXTENSIONS,
    RUST_EXTENSIONS,
    SKIP_DIRS,
    SUPPORTED_EXTENSIONS,
    TERRAFORM_EXTENSIONS,
    WORK_QUEUE_MAXSIZE,
    WORKER_QUEUE_TIMEOUT,
    WORKER_SHUTDOWN_TIMEOUT,
)
from hackmenot.parsers.golang import GoParser
from hackmenot.parsers.java import JavaParser
from hackmenot.parsers.javascript import JavaScriptParser
from hackmenot.parsers.python import PythonParser
from hackmenot.parsers.rust import RustParser
from hackmenot.parsers.terraform import TerraformParser
from hackmenot.rules.engine import RulesEngine
from hackmenot.rules.registry import RuleRegistry


@dataclass
class ScanResults:
    """Results from parallel scan."""

    findings: list[tuple[Path, list[Any]]]
    files_scanned: int

    @property
    def total_findings(self) -> int:
        """Count total findings across all files."""
        return sum(len(f) for _, f in self.findings)


class ScanWorker:
    """Worker process that scans files from a work queue."""

    def __init__(
        self,
        work_queue: Any,  # queue.Queue or multiprocessing.Queue
        results_queue: Any,  # queue.Queue or multiprocessing.Queue
        rules_engine: Any,  # RulesEngine instance
    ) -> None:
        """Initialize the ScanWorker.

        Args:
            work_queue: Queue to pull file paths from.
            results_queue: Queue to push scan results to.
            rules_engine: RulesEngine instance with registered rules.
        """
        self.work_queue = work_queue
        self.results_queue = results_queue
        self.rules_engine = rules_engine
        self._parsers: dict[str, Any] = {}

    def run(self) -> None:
        """Run the worker loop.

        Continuously pulls file paths from work queue, scans them,
        and pushes results to results queue. Exits when receiving
        poison pill (None).
        """
        while True:
            try:
                file_path = self.work_queue.get(timeout=WORKER_QUEUE_TIMEOUT)
            except queue.Empty:
                # No work available, keep waiting
                continue

            # Poison pill: signal to shutdown
            if file_path is None:
                break

            # Scan the file and push results
            findings = self._scan_file(file_path)
            self.results_queue.put((file_path, findings))

    def _get_parser(self, file_path: Path) -> Any:
        """Get or create cached parser for file.

        Detects the language from file extension and returns the appropriate
        parser instance. Parsers are cached per language and reused across
        multiple files in the same worker.

        Args:
            file_path: Path to the file to parse.

        Returns:
            Parser instance for the file's language, or None if unsupported.
        """
        suffix = file_path.suffix

        # Determine language and parser class from extension
        lang: str
        parser_class: type[Any]

        if suffix in PYTHON_EXTENSIONS:
            lang = "python"
            parser_class = PythonParser
        elif suffix in JS_EXTENSIONS:
            lang = "javascript"
            parser_class = JavaScriptParser
        elif suffix in GO_EXTENSIONS:
            lang = "go"
            parser_class = GoParser
        elif suffix in RUST_EXTENSIONS:
            lang = "rust"
            parser_class = RustParser
        elif suffix in JAVA_EXTENSIONS:
            lang = "java"
            parser_class = JavaParser
        elif suffix in TERRAFORM_EXTENSIONS:
            lang = "terraform"
            parser_class = TerraformParser
        else:
            # Unsupported file extension
            return None

        # Get or create cached parser for this language
        if lang not in self._parsers:
            self._parsers[lang] = parser_class()

        return self._parsers[lang]

    def _scan_file(self, file_path: Path) -> list[Any]:
        """Scan a single file for security issues.

        Parses the file using the appropriate parser and checks it against
        all registered rules. Handles errors gracefully without crashing
        the worker process.

        Args:
            file_path: Path to the file to scan.

        Returns:
            List of findings from rule checks. Returns empty list if:
            - File cannot be parsed (parse error)
            - File is binary (UnicodeDecodeError)
            - Parser not available for file type
            - Rule checking fails
            - No issues found
        """
        try:
            # Get parser for this file type
            parser = self._get_parser(file_path)
            if parser is None:
                # No parser available for this file type
                return []

            # Parse the file
            parse_result = parser.parse_file(file_path)

            # Check if parse failed
            if parse_result is None or parse_result.has_error:
                # Parse error - skip this file
                return []

            # Check rules against parsed AST
            findings: list[Any] = self.rules_engine.check(parse_result, file_path)
            return findings

        except UnicodeDecodeError:
            # Binary file - skip
            return []
        except (OSError, ValueError, RuntimeError):
            # OSError: file access issues
            # ValueError: invalid parse result
            # RuntimeError: rule check errors
            # Don't crash the worker on individual file errors
            return []


class ParallelScanner:
    """Parallel scanner for processing files concurrently."""

    def __init__(
        self, num_workers: int | None = None, rules_engine: RulesEngine | None = None
    ) -> None:
        """Initialize the ParallelScanner.

        Args:
            num_workers: Number of worker processes to use.
                        Defaults to DEFAULT_WORKERS if None.
            rules_engine: RulesEngine instance with registered rules.
                         If None, automatically loads all rules from RuleRegistry.
        """
        self.num_workers = num_workers if num_workers is not None else DEFAULT_WORKERS

        # Load rules if not provided
        if rules_engine is None:
            rule_registry = RuleRegistry()
            rule_registry.load_all()
            self.rules_engine = RulesEngine()
            for rule in rule_registry.get_all_rules():
                self.rules_engine.register_rule(rule)
        else:
            self.rules_engine = rules_engine

        self.work_queue: multiprocessing.Queue[Path | None] = multiprocessing.Queue(
            maxsize=WORK_QUEUE_MAXSIZE
        )
        self.results_queue: multiprocessing.Queue[tuple[Path, list[Any]]] = multiprocessing.Queue()
        self._workers: list[multiprocessing.Process] = []

    def _discover_files(self, paths: list[Path]) -> Iterator[Path]:
        """Discover files to scan from input paths.

        Uses Path.rglob() for recursive file discovery. Filters by supported
        extensions during discovery to avoid loading all paths into memory.
        Skips symlinks that escape the base path for security.

        Args:
            paths: List of file or directory paths to scan.

        Yields:
            Path objects for files that should be scanned.
        """
        for path in paths:
            # If path is a file, check if it has a supported extension
            if path.is_file():
                if path.suffix in SUPPORTED_EXTENSIONS:
                    yield path
                continue

            # If path is a directory, recursively discover files
            if path.is_dir():
                base_path = path.resolve()

                for file_path in path.rglob("*"):
                    # Skip if not a file
                    if not file_path.is_file():
                        continue

                    # Skip if extension not supported
                    if file_path.suffix not in SUPPORTED_EXTENSIONS:
                        continue

                    # Skip files in SKIP_DIRS or .egg-info directories
                    if any(
                        part in SKIP_DIRS or part.endswith(".egg-info") for part in file_path.parts
                    ):
                        continue

                    # Symlink escape protection: ensure resolved path is within base
                    try:
                        resolved = file_path.resolve()
                        if not resolved.is_relative_to(base_path):
                            continue
                    except (OSError, ValueError):
                        continue

                    yield file_path

    def _distribute_work(self, files: Iterator[Path]) -> None:
        """Distribute files to work queue for workers to process.

        Enqueues file paths to the work queue. Blocks if queue is full
        (provides backpressure to prevent unbounded memory growth).

        Args:
            files: Iterator of file paths to distribute.
        """
        for file_path in files:
            self.work_queue.put(file_path)

    def _send_poison_pills(self) -> None:
        """Send poison pills to work queue to signal workers to exit.

        Sends one None (poison pill) per worker to gracefully shutdown
        all worker processes.
        """
        for _ in range(self.num_workers):
            self.work_queue.put(None)

    def _start_workers(self) -> None:
        """Start worker processes.

        Creates and starts num_workers Process instances. Each process
        runs the ScanWorker.run() method in its own process space.
        Workers are non-daemon for clean shutdown.
        """
        for _ in range(self.num_workers):
            worker_process = multiprocessing.Process(
                target=_worker_target,
                args=(self.work_queue, self.results_queue, self.rules_engine),
            )
            worker_process.start()
            self._workers.append(worker_process)

    def _stop_workers(self) -> None:
        """Stop worker processes.

        Waits for workers to finish gracefully (via poison pills).
        If workers don't exit within WORKER_SHUTDOWN_TIMEOUT seconds,
        force terminates them.
        """
        # Wait for all workers to finish
        for worker in self._workers:
            worker.join(timeout=WORKER_SHUTDOWN_TIMEOUT)

            # Force terminate if worker didn't exit cleanly
            if worker.is_alive():
                worker.terminate()

    def _collect_results(self, expected_count: int) -> list[tuple[Path, list[Any]]]:
        """Collect results from workers.

        Pulls results from the results queue until expected_count files
        have been processed or a timeout occurs. Handles queue.Empty
        exceptions gracefully to support partial collection if workers
        fail or timeout.

        Args:
            expected_count: Number of files expected to be processed.

        Returns:
            List of (file_path, findings) tuples collected from workers.
        """
        results = []
        for _ in range(expected_count):
            try:
                file_path, findings = self.results_queue.get(timeout=30.0)
                results.append((file_path, findings))
            except queue.Empty:
                # Worker might have crashed or timeout reached
                break
        return results

    def scan(self, paths: list[Path]) -> ScanResults:
        """Scan files for security issues using parallel workers.

        This is the main entry point that orchestrates the entire parallel
        scanning pipeline:
        1. Discovers files to scan
        2. Starts worker processes
        3. Distributes files to workers
        4. Collects results
        5. Stops workers cleanly

        Args:
            paths: List of file or directory paths to scan.

        Returns:
            ScanResults containing findings and scan statistics.
        """
        # 1. Discover files (convert generator to list to count files)
        files = list(self._discover_files(paths))

        # If no files to scan, return empty results
        if not files:
            return ScanResults(findings=[], files_scanned=0)

        # 2. Start workers
        self._start_workers()

        try:
            # 3. Distribute work to workers
            self._distribute_work(iter(files))

            # 4. Signal completion to workers
            self._send_poison_pills()

            # 5. Collect results from workers
            results = self._collect_results(expected_count=len(files))

            return ScanResults(findings=results, files_scanned=len(results))
        finally:
            # 6. Cleanup workers (always runs even if exception occurs)
            self._stop_workers()


def _worker_target(
    work_queue: multiprocessing.Queue[Path | None],
    results_queue: multiprocessing.Queue[tuple[Path, list[Any]]],
    rules_engine: RulesEngine,
) -> None:
    """Target function for worker processes.

    Creates a ScanWorker instance and runs its worker loop.

    Args:
        work_queue: Queue to pull file paths from.
        results_queue: Queue to push scan results to.
        rules_engine: RulesEngine instance with registered rules.
    """
    worker = ScanWorker(work_queue, results_queue, rules_engine)
    worker.run()
