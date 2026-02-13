"""Parallel scanning implementation using multiprocessing."""

from __future__ import annotations

import multiprocessing
import queue
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from hackmenot.core.constants import (
    DEFAULT_WORKERS,
    SKIP_DIRS,
    SUPPORTED_EXTENSIONS,
    WORK_QUEUE_MAXSIZE,
    WORKER_QUEUE_TIMEOUT,
)


class ScanWorker:
    """Worker process that scans files from a work queue."""

    def __init__(
        self,
        work_queue: Any,  # queue.Queue or multiprocessing.Queue
        results_queue: Any,  # queue.Queue or multiprocessing.Queue
    ) -> None:
        """Initialize the ScanWorker.

        Args:
            work_queue: Queue to pull file paths from.
            results_queue: Queue to push scan results to.
        """
        self.work_queue = work_queue
        self.results_queue = results_queue

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

    def _scan_file(self, file_path: Path) -> list[Any]:
        """Scan a single file for security issues.

        Args:
            file_path: Path to the file to scan.

        Returns:
            List of findings (empty for now, actual scanning in Task 9).
        """
        # Placeholder: actual scanning logic will be implemented in Task 9
        return []


class ParallelScanner:
    """Parallel scanner for processing files concurrently."""

    def __init__(self, num_workers: int | None = None) -> None:
        """Initialize the ParallelScanner.

        Args:
            num_workers: Number of worker processes to use.
                        Defaults to DEFAULT_WORKERS if None.
        """
        self.num_workers = num_workers if num_workers is not None else DEFAULT_WORKERS
        self.work_queue: multiprocessing.Queue[Path | None] = multiprocessing.Queue(
            maxsize=WORK_QUEUE_MAXSIZE
        )
        self.results_queue: multiprocessing.Queue[tuple[Path, list[Any]]] = multiprocessing.Queue()

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
