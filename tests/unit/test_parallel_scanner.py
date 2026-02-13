"""Tests for ParallelScanner class."""

import queue
from pathlib import Path
from typing import Any

from hackmenot.core.constants import DEFAULT_WORKERS
from hackmenot.core.parallel_scanner import ParallelScanner, ScanWorker


class TestParallelScannerInit:
    """Test ParallelScanner initialization."""

    def test_default_worker_count(self) -> None:
        """Test that ParallelScanner defaults to DEFAULT_WORKERS."""
        scanner = ParallelScanner()
        assert scanner.num_workers == DEFAULT_WORKERS

    def test_custom_worker_count(self) -> None:
        """Test that ParallelScanner accepts custom worker count."""
        custom_count = 4
        scanner = ParallelScanner(num_workers=custom_count)
        assert scanner.num_workers == custom_count

    def test_explicit_none_uses_default(self) -> None:
        """Test that explicitly passing None uses DEFAULT_WORKERS."""
        scanner = ParallelScanner(num_workers=None)
        assert scanner.num_workers == DEFAULT_WORKERS


class TestScanWorker:
    """Test ScanWorker class."""

    def test_worker_pulls_from_work_queue(self) -> None:
        """Test that worker pulls file paths from work queue."""
        work_queue: queue.Queue[Path | None] = queue.Queue()
        results_queue: queue.Queue[tuple[Path, list[Any]]] = queue.Queue()

        # Add a file and poison pill
        test_file = Path("/fake/path/test.py")
        work_queue.put(test_file)
        work_queue.put(None)  # Poison pill to stop worker

        worker = ScanWorker(work_queue, results_queue)
        worker.run()

        # Worker should have processed the file and put result
        assert not results_queue.empty()
        file_path, findings = results_queue.get(timeout=1.0)
        assert file_path == test_file
        assert isinstance(findings, list)

    def test_worker_handles_poison_pill(self) -> None:
        """Test that worker exits when receiving None (poison pill)."""
        work_queue: queue.Queue[Path | None] = queue.Queue()
        results_queue: queue.Queue[tuple[Path, list[Any]]] = queue.Queue()

        # Add only poison pill
        work_queue.put(None)

        worker = ScanWorker(work_queue, results_queue)
        worker.run()

        # Worker should exit cleanly without putting anything to results
        assert results_queue.empty()

    def test_worker_processes_multiple_files(self) -> None:
        """Test that worker processes multiple files before poison pill."""
        work_queue: queue.Queue[Path | None] = queue.Queue()
        results_queue: queue.Queue[tuple[Path, list[Any]]] = queue.Queue()

        # Add multiple files and poison pill
        files = [Path("/fake/file1.py"), Path("/fake/file2.js"), Path("/fake/file3.go")]
        for file in files:
            work_queue.put(file)
        work_queue.put(None)  # Poison pill

        worker = ScanWorker(work_queue, results_queue)
        worker.run()

        # Worker should have processed all files
        processed_files = []
        while not results_queue.empty():
            file_path, findings = results_queue.get(timeout=1.0)
            processed_files.append(file_path)
            assert isinstance(findings, list)

        assert len(processed_files) == len(files)
        assert set(processed_files) == set(files)

    def test_worker_handles_empty_queue_timeout(self) -> None:
        """Test that worker handles queue timeout gracefully."""
        work_queue: queue.Queue[Path | None] = queue.Queue()
        results_queue: queue.Queue[tuple[Path, list[Any]]] = queue.Queue()

        # Don't put anything in queue initially, then add poison pill after delay
        worker = ScanWorker(work_queue, results_queue)

        # Put poison pill immediately so worker exits quickly
        work_queue.put(None)

        # Should not raise exception, should exit cleanly
        worker.run()
        assert results_queue.empty()
