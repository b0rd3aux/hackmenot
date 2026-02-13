"""Tests for ParallelScanner class."""

import multiprocessing
import queue
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from hackmenot.core.constants import DEFAULT_WORKERS, WORK_QUEUE_MAXSIZE
from hackmenot.core.parallel_scanner import ParallelScanner, ScanResults, ScanWorker


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

    def test_initializes_work_queue_with_maxsize(self) -> None:
        """Test that work_queue is initialized with maxsize=WORK_QUEUE_MAXSIZE."""
        scanner = ParallelScanner()
        assert isinstance(scanner.work_queue, multiprocessing.queues.Queue)
        # Note: multiprocessing.Queue doesn't expose maxsize directly,
        # but we can verify it's bounded by trying to fill it
        assert scanner.work_queue._maxsize == WORK_QUEUE_MAXSIZE

    def test_initializes_results_queue_unbounded(self) -> None:
        """Test that results_queue is initialized as unbounded."""
        scanner = ParallelScanner()
        assert isinstance(scanner.results_queue, multiprocessing.queues.Queue)
        # multiprocessing.Queue() without maxsize arg defaults to a very large value (effectively unbounded)
        # The exact value is platform-dependent, but should be much larger than work_queue
        assert scanner.results_queue._maxsize > scanner.work_queue._maxsize


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


class TestFileDiscovery:
    """Test file discovery functionality."""

    def test_discovers_python_files_recursively(self, tmp_path: Path) -> None:
        """Test that _discover_files finds .py files recursively."""
        # Create test structure
        (tmp_path / "test.py").touch()
        (tmp_path / "subdir").mkdir()
        (tmp_path / "subdir" / "nested.py").touch()

        scanner = ParallelScanner()
        files = list(scanner._discover_files([tmp_path]))

        assert len(files) == 2
        assert tmp_path / "test.py" in files
        assert tmp_path / "subdir" / "nested.py" in files

    def test_discovers_multiple_language_extensions(self, tmp_path: Path) -> None:
        """Test that _discover_files finds files with different extensions."""
        # Create files with different extensions
        (tmp_path / "script.py").touch()
        (tmp_path / "app.js").touch()
        (tmp_path / "main.go").touch()
        (tmp_path / "lib.rs").touch()
        (tmp_path / "App.java").touch()
        (tmp_path / "main.tf").touch()

        scanner = ParallelScanner()
        files = list(scanner._discover_files([tmp_path]))

        assert len(files) == 6
        assert tmp_path / "script.py" in files
        assert tmp_path / "app.js" in files
        assert tmp_path / "main.go" in files
        assert tmp_path / "lib.rs" in files
        assert tmp_path / "App.java" in files
        assert tmp_path / "main.tf" in files

    def test_yields_files_lazily(self, tmp_path: Path) -> None:
        """Test that _discover_files returns a generator, not a list."""
        (tmp_path / "test.py").touch()

        scanner = ParallelScanner()
        result = scanner._discover_files([tmp_path])

        # Should be a generator/iterator, not a list
        assert hasattr(result, "__iter__")
        assert hasattr(result, "__next__")

    def test_filters_out_unsupported_extensions(self, tmp_path: Path) -> None:
        """Test that _discover_files ignores files with unsupported extensions."""
        # Create supported and unsupported files
        (tmp_path / "script.py").touch()
        (tmp_path / "readme.md").touch()
        (tmp_path / "data.json").touch()
        (tmp_path / "config.yaml").touch()
        (tmp_path / "binary.exe").touch()

        scanner = ParallelScanner()
        files = list(scanner._discover_files([tmp_path]))

        # Should only find the .py file
        assert len(files) == 1
        assert tmp_path / "script.py" in files

    def test_handles_multiple_input_paths(self, tmp_path: Path) -> None:
        """Test that _discover_files handles multiple input directories."""
        # Create two separate directories
        dir1 = tmp_path / "dir1"
        dir2 = tmp_path / "dir2"
        dir1.mkdir()
        dir2.mkdir()

        (dir1 / "file1.py").touch()
        (dir2 / "file2.py").touch()

        scanner = ParallelScanner()
        files = list(scanner._discover_files([dir1, dir2]))

        assert len(files) == 2
        assert dir1 / "file1.py" in files
        assert dir2 / "file2.py" in files

    def test_skips_symlinks_that_escape_base_path(self, tmp_path: Path) -> None:
        """Test that _discover_files skips symlinks that point outside base path."""
        # Create a directory structure
        base_dir = tmp_path / "base"
        base_dir.mkdir()
        (base_dir / "safe.py").touch()

        # Create a directory outside base
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        (outside_dir / "escape.py").touch()

        # Create a symlink that escapes base_dir
        escape_link = base_dir / "escape_link"
        escape_link.symlink_to(outside_dir / "escape.py")

        scanner = ParallelScanner()
        files = list(scanner._discover_files([base_dir]))

        # Should only find safe.py, not the symlink target
        assert len(files) == 1
        assert base_dir / "safe.py" in files
        assert escape_link not in files
        assert outside_dir / "escape.py" not in files

    def test_handles_empty_directory(self, tmp_path: Path) -> None:
        """Test that _discover_files handles directories with no matching files."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        scanner = ParallelScanner()
        files = list(scanner._discover_files([empty_dir]))

        assert len(files) == 0

    def test_handles_single_file_path(self, tmp_path: Path) -> None:
        """Test that _discover_files handles a single file path."""
        test_file = tmp_path / "test.py"
        test_file.touch()

        scanner = ParallelScanner()
        files = list(scanner._discover_files([test_file]))

        assert len(files) == 1
        assert test_file in files

    def test_skips_common_directories(self, tmp_path: Path) -> None:
        """Test that _discover_files skips common directories like node_modules."""
        # Create files in directories that should be skipped
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "lib.js").touch()
        (tmp_path / "__pycache__").mkdir()
        (tmp_path / "__pycache__" / "cache.py").touch()
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config").touch()

        # Create a file that should be found
        (tmp_path / "app.py").touch()

        scanner = ParallelScanner()
        files = list(scanner._discover_files([tmp_path]))

        # Should only find app.py, not files in skipped directories
        assert len(files) == 1
        assert tmp_path / "app.py" in files


class TestWorkDistribution:
    """Test work distribution functionality."""

    def test_distribute_work_enqueues_files(self, tmp_path: Path) -> None:
        """Test that _distribute_work enqueues all discovered files."""
        # Create test files
        (tmp_path / "file1.py").touch()
        (tmp_path / "file2.py").touch()
        (tmp_path / "file3.py").touch()

        scanner = ParallelScanner()
        files = list(scanner._discover_files([tmp_path]))

        # Distribute work
        scanner._distribute_work(iter(files))

        # Check that all files were enqueued - read exactly len(files) items
        enqueued_files = []
        for _ in range(len(files)):
            try:
                file = scanner.work_queue.get(timeout=1.0)
                enqueued_files.append(file)
            except queue.Empty:
                break

        assert len(enqueued_files) == 3
        assert set(enqueued_files) == set(files)

    def test_distribute_work_handles_empty_iterator(self) -> None:
        """Test that _distribute_work handles empty file iterator."""
        scanner = ParallelScanner()
        empty_files = iter([])

        # Should not raise exception
        scanner._distribute_work(empty_files)

        # Queue should be empty
        assert scanner.work_queue.empty()

    def test_send_poison_pills_sends_correct_count(self) -> None:
        """Test that _send_poison_pills sends one None per worker."""
        scanner = ParallelScanner(num_workers=4)

        scanner._send_poison_pills()

        # Count poison pills - read exactly num_workers items
        poison_pills = []
        for _ in range(scanner.num_workers):
            try:
                item = scanner.work_queue.get(timeout=1.0)
                if item is None:
                    poison_pills.append(item)
            except queue.Empty:
                break

        assert len(poison_pills) == 4

    def test_send_poison_pills_respects_worker_count(self) -> None:
        """Test that poison pills match configured worker count."""
        for worker_count in [1, 2, 4, 8]:
            scanner = ParallelScanner(num_workers=worker_count)
            scanner._send_poison_pills()

            # Count poison pills - read exactly worker_count items
            pills = 0
            for _ in range(worker_count):
                try:
                    item = scanner.work_queue.get(timeout=1.0)
                    if item is None:
                        pills += 1
                except queue.Empty:
                    break

            assert pills == worker_count


class TestWorkerLifecycle:
    """Test worker lifecycle management."""

    def test_start_workers_creates_correct_number_of_processes(self) -> None:
        """Test that _start_workers creates correct number of worker processes."""
        scanner = ParallelScanner(num_workers=4)

        scanner._start_workers()

        assert len(scanner._workers) == 4
        assert all(isinstance(w, multiprocessing.Process) for w in scanner._workers)

        # Clean up workers
        scanner._send_poison_pills()
        scanner._stop_workers()

    def test_start_workers_actually_starts_processes(self) -> None:
        """Test that _start_workers starts all worker processes."""
        scanner = ParallelScanner(num_workers=2)

        scanner._start_workers()

        # Give processes a moment to start
        time.sleep(0.1)

        # All workers should be alive
        assert all(w.is_alive() for w in scanner._workers)

        # Clean up workers
        scanner._send_poison_pills()
        scanner._stop_workers()

    def test_workers_are_non_daemon(self) -> None:
        """Test that worker processes are non-daemon for clean shutdown."""
        scanner = ParallelScanner(num_workers=2)

        scanner._start_workers()

        # All workers should be non-daemon (daemon=False is default)
        assert all(not w.daemon for w in scanner._workers)

        # Clean up workers
        scanner._send_poison_pills()
        scanner._stop_workers()

    def test_stop_workers_waits_for_workers_to_finish(self) -> None:
        """Test that _stop_workers waits for workers to finish."""
        scanner = ParallelScanner(num_workers=2)

        scanner._start_workers()
        time.sleep(0.1)  # Let workers start

        # Send poison pills and stop
        scanner._send_poison_pills()
        scanner._stop_workers()

        # All workers should be stopped (not alive)
        assert all(not w.is_alive() for w in scanner._workers)

    def test_stop_workers_handles_already_stopped_workers(self) -> None:
        """Test that _stop_workers handles workers that already exited."""
        scanner = ParallelScanner(num_workers=2)

        scanner._start_workers()
        time.sleep(0.1)

        # Send poison pills and wait for workers to exit naturally
        scanner._send_poison_pills()
        time.sleep(0.5)  # Let workers finish

        # Now stop should still work even though workers already exited
        scanner._stop_workers()

        assert all(not w.is_alive() for w in scanner._workers)

    @patch("multiprocessing.Process")
    def test_worker_target_creates_scan_worker(self, mock_process_class: MagicMock) -> None:
        """Test that worker processes run ScanWorker.run()."""
        scanner = ParallelScanner(num_workers=2)

        scanner._start_workers()

        # Verify Process was created with correct target and args
        assert mock_process_class.call_count == 2

        for call in mock_process_class.call_args_list:
            kwargs = call[1]
            assert "target" in kwargs
            assert "args" in kwargs
            # Args should be (work_queue, results_queue)
            assert len(kwargs["args"]) == 2

        # Clean up (if workers were actually started)
        scanner._send_poison_pills()
        if hasattr(scanner, "_workers") and scanner._workers:
            for w in scanner._workers:
                if hasattr(w, "is_alive"):
                    if w.is_alive():
                        w.terminate()

    def test_workers_actually_process_work(self) -> None:
        """Integration test: workers actually pull from queue and process."""
        scanner = ParallelScanner(num_workers=2)

        # Start workers
        scanner._start_workers()
        time.sleep(0.1)  # Let workers start

        # Add some work
        test_files = [Path("/fake/file1.py"), Path("/fake/file2.py"), Path("/fake/file3.py")]
        for file in test_files:
            scanner.work_queue.put(file)

        # Give workers time to process
        time.sleep(0.5)

        # Collect results
        results = []
        while not scanner.results_queue.empty():
            try:
                result = scanner.results_queue.get(timeout=0.1)
                results.append(result)
            except queue.Empty:
                break

        # Should have processed all files
        assert len(results) == len(test_files)

        # Clean up
        scanner._send_poison_pills()
        scanner._stop_workers()

    def test_stop_workers_terminates_hung_workers(self) -> None:
        """Test that _stop_workers terminates workers that don't exit gracefully."""
        # This test verifies timeout behavior - we'll mock join to simulate hung worker
        scanner = ParallelScanner(num_workers=1)

        scanner._start_workers()
        time.sleep(0.1)

        # Create a mock worker that simulates hanging (never exits)
        hung_worker = MagicMock(spec=multiprocessing.Process)
        hung_worker.is_alive.return_value = True
        hung_worker.join.return_value = None  # join returns but worker still alive

        # Replace real worker with hung worker
        real_workers = scanner._workers
        scanner._workers = [hung_worker]

        # Stop should terminate the hung worker
        scanner._stop_workers()

        # Should have called join and then terminate
        hung_worker.join.assert_called_once()
        hung_worker.terminate.assert_called_once()

        # Clean up real workers
        scanner._workers = real_workers
        scanner._send_poison_pills()
        for w in scanner._workers:
            w.join(timeout=1.0)
            if w.is_alive():
                w.terminate()


class TestResultsCollection:
    """Test results collection and aggregation."""

    def test_collect_results_pulls_from_results_queue(self) -> None:
        """Test that _collect_results pulls results from results queue."""
        scanner = ParallelScanner()

        # Add a result to the queue
        test_file = Path("/fake/test.py")
        test_findings = [{"rule": "test-rule", "severity": "high"}]
        scanner.results_queue.put((test_file, test_findings))

        # Collect results
        results = scanner._collect_results(expected_count=1)

        assert len(results) == 1
        assert results[0] == (test_file, test_findings)

    def test_collect_results_collects_multiple_results(self) -> None:
        """Test that _collect_results collects multiple results."""
        scanner = ParallelScanner()

        # Add multiple results
        test_results = [
            (Path("/fake/file1.py"), [{"rule": "rule1"}]),
            (Path("/fake/file2.js"), [{"rule": "rule2"}]),
            (Path("/fake/file3.go"), [{"rule": "rule3"}]),
        ]

        for file_path, findings in test_results:
            scanner.results_queue.put((file_path, findings))

        # Collect all results
        results = scanner._collect_results(expected_count=3)

        assert len(results) == 3
        # Compare as sorted lists (order may vary)
        assert sorted(results, key=lambda x: str(x[0])) == sorted(
            test_results, key=lambda x: str(x[0])
        )

    def test_collect_results_handles_empty_findings(self) -> None:
        """Test that _collect_results handles files with no findings."""
        scanner = ParallelScanner()

        # Add result with empty findings
        test_file = Path("/fake/clean.py")
        scanner.results_queue.put((test_file, []))

        results = scanner._collect_results(expected_count=1)

        assert len(results) == 1
        assert results[0] == (test_file, [])

    def test_collect_results_handles_timeout_gracefully(self) -> None:
        """Test that _collect_results handles queue timeout without crashing."""
        scanner = ParallelScanner()

        # Don't add any results to queue
        # Collect should timeout but not crash
        results = scanner._collect_results(expected_count=2)

        # Should return empty list (no results collected before timeout)
        assert len(results) == 0

    def test_collect_results_returns_partial_results_on_timeout(self) -> None:
        """Test that _collect_results returns partial results if some workers fail."""
        scanner = ParallelScanner()

        # Add only some of the expected results
        scanner.results_queue.put((Path("/fake/file1.py"), []))
        scanner.results_queue.put((Path("/fake/file2.py"), []))
        # Don't add the third result - simulates worker failure

        # Should return the 2 results we got before timeout
        results = scanner._collect_results(expected_count=3)

        assert len(results) == 2

    def test_collect_results_respects_expected_count(self) -> None:
        """Test that _collect_results collects exactly expected_count results."""
        scanner = ParallelScanner()

        # Add more results than expected
        for i in range(10):
            scanner.results_queue.put((Path(f"/fake/file{i}.py"), []))

        # Collect only 5
        results = scanner._collect_results(expected_count=5)

        assert len(results) == 5

        # Queue should still have remaining results
        assert not scanner.results_queue.empty()

    def test_collect_results_returns_correct_data_structure(self) -> None:
        """Test that _collect_results returns list of (Path, list) tuples."""
        scanner = ParallelScanner()

        test_file = Path("/fake/test.py")
        test_findings = [{"rule": "test"}]
        scanner.results_queue.put((test_file, test_findings))

        results = scanner._collect_results(expected_count=1)

        # Should be a list
        assert isinstance(results, list)

        # Each item should be a tuple of (Path, list)
        assert len(results) == 1
        file_path, findings = results[0]
        assert isinstance(file_path, Path)
        assert isinstance(findings, list)


class TestScanMethod:
    """Test the main scan() method orchestration."""

    def test_scan_returns_scan_results_object(self, tmp_path: Path) -> None:
        """Test that scan() returns a ScanResults object."""
        # Create a test file
        (tmp_path / "test.py").touch()

        scanner = ParallelScanner(num_workers=1)
        results = scanner.scan([tmp_path])

        assert isinstance(results, ScanResults)

    def test_scan_discovers_files(self, tmp_path: Path) -> None:
        """Test that scan() discovers files correctly."""
        # Create test files
        (tmp_path / "file1.py").touch()
        (tmp_path / "file2.py").touch()

        scanner = ParallelScanner(num_workers=1)
        results = scanner.scan([tmp_path])

        assert results.files_scanned == 2

    def test_scan_starts_and_stops_workers(self, tmp_path: Path) -> None:
        """Test that scan() properly manages worker lifecycle."""
        (tmp_path / "test.py").touch()

        scanner = ParallelScanner(num_workers=2)

        # Before scan, no workers
        assert len(scanner._workers) == 0

        results = scanner.scan([tmp_path])

        # After scan, workers should be started and stopped
        assert len(scanner._workers) == 2
        # All workers should be stopped
        assert all(not w.is_alive() for w in scanner._workers)

    def test_scan_distributes_work_to_queue(self, tmp_path: Path) -> None:
        """Test that scan() distributes work to workers."""
        # Create multiple test files
        (tmp_path / "file1.py").touch()
        (tmp_path / "file2.py").touch()
        (tmp_path / "file3.py").touch()

        scanner = ParallelScanner(num_workers=2)
        results = scanner.scan([tmp_path])

        # Should have scanned all files
        assert results.files_scanned == 3

    def test_scan_collects_results(self, tmp_path: Path) -> None:
        """Test that scan() collects results from workers."""
        (tmp_path / "test.py").touch()

        scanner = ParallelScanner(num_workers=1)
        results = scanner.scan([tmp_path])

        # Should have findings list (even if empty for now)
        assert isinstance(results.findings, list)
        assert len(results.findings) == 1
        # Each result should be (Path, list) tuple
        file_path, findings = results.findings[0]
        assert isinstance(file_path, Path)
        assert isinstance(findings, list)

    def test_scan_stops_workers_on_error(self, tmp_path: Path) -> None:
        """Test that scan() stops workers even if an error occurs."""
        (tmp_path / "test.py").touch()

        scanner = ParallelScanner(num_workers=2)

        # Mock _collect_results to raise an exception
        original_collect = scanner._collect_results

        def failing_collect(expected_count: int) -> list[tuple[Path, list[Any]]]:
            raise RuntimeError("Simulated error")

        scanner._collect_results = failing_collect  # type: ignore

        try:
            scanner.scan([tmp_path])
            assert False, "Should have raised RuntimeError"
        except RuntimeError:
            # Workers should still be stopped despite the error
            assert all(not w.is_alive() for w in scanner._workers)

    def test_scan_with_empty_directory(self, tmp_path: Path) -> None:
        """Test that scan() handles empty directory gracefully."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        scanner = ParallelScanner(num_workers=2)
        results = scanner.scan([empty_dir])

        # Should return empty results
        assert results.files_scanned == 0
        assert len(results.findings) == 0
        # Workers should not be started if no files
        assert len(scanner._workers) == 0

    def test_scan_with_no_matching_files(self, tmp_path: Path) -> None:
        """Test that scan() handles directory with no matching files."""
        # Create files with unsupported extensions
        (tmp_path / "readme.md").touch()
        (tmp_path / "data.json").touch()

        scanner = ParallelScanner(num_workers=2)
        results = scanner.scan([tmp_path])

        # Should return empty results
        assert results.files_scanned == 0
        assert len(results.findings) == 0

    def test_scan_end_to_end_with_real_files(self, tmp_path: Path) -> None:
        """Integration test: scan actual test files end-to-end."""
        # Create test files with different extensions
        (tmp_path / "script.py").write_text("print('hello')")
        (tmp_path / "app.js").write_text("console.log('hello');")
        (tmp_path / "main.go").write_text("package main\nfunc main() {}")

        scanner = ParallelScanner(num_workers=2)
        results = scanner.scan([tmp_path])

        # Should have scanned all 3 files
        assert results.files_scanned == 3

        # Should have 3 results (one per file)
        assert len(results.findings) == 3

        # Each result should be (Path, list) with empty findings for now
        for file_path, findings in results.findings:
            assert isinstance(file_path, Path)
            assert file_path.exists()
            assert isinstance(findings, list)
            # For now, findings should be empty (actual scanning is Task 9)
            assert len(findings) == 0

    def test_scan_results_total_findings_property(self, tmp_path: Path) -> None:
        """Test that ScanResults.total_findings counts findings correctly."""
        (tmp_path / "test.py").touch()

        scanner = ParallelScanner(num_workers=1)
        results = scanner.scan([tmp_path])

        # For now, total_findings should be 0 (no actual scanning yet)
        assert results.total_findings == 0

    def test_scan_accepts_multiple_paths(self, tmp_path: Path) -> None:
        """Test that scan() accepts multiple input paths."""
        dir1 = tmp_path / "dir1"
        dir2 = tmp_path / "dir2"
        dir1.mkdir()
        dir2.mkdir()

        (dir1 / "file1.py").touch()
        (dir2 / "file2.py").touch()

        scanner = ParallelScanner(num_workers=2)
        results = scanner.scan([dir1, dir2])

        assert results.files_scanned == 2

    def test_scan_accepts_file_paths_directly(self, tmp_path: Path) -> None:
        """Test that scan() accepts file paths directly."""
        file1 = tmp_path / "file1.py"
        file2 = tmp_path / "file2.py"
        file1.touch()
        file2.touch()

        scanner = ParallelScanner(num_workers=2)
        results = scanner.scan([file1, file2])

        assert results.files_scanned == 2


class TestParserCaching:
    """Test parser caching in ScanWorker."""

    def test_get_parser_returns_python_parser_for_py_file(self) -> None:
        """Test that _get_parser returns PythonParser for .py files."""
        from hackmenot.parsers.python import PythonParser

        work_queue: queue.Queue[Path | None] = queue.Queue()
        results_queue: queue.Queue[tuple[Path, list[Any]]] = queue.Queue()
        worker = ScanWorker(work_queue, results_queue)

        parser = worker._get_parser(Path("/fake/test.py"))

        assert parser is not None
        assert isinstance(parser, PythonParser)

    def test_get_parser_returns_js_parser_for_js_file(self) -> None:
        """Test that _get_parser returns JavaScriptParser for .js files."""
        from hackmenot.parsers.javascript import JavaScriptParser

        work_queue: queue.Queue[Path | None] = queue.Queue()
        results_queue: queue.Queue[tuple[Path, list[Any]]] = queue.Queue()
        worker = ScanWorker(work_queue, results_queue)

        parser = worker._get_parser(Path("/fake/app.js"))

        assert parser is not None
        assert isinstance(parser, JavaScriptParser)

    def test_get_parser_returns_go_parser_for_go_file(self) -> None:
        """Test that _get_parser returns GoParser for .go files."""
        from hackmenot.parsers.golang import GoParser

        work_queue: queue.Queue[Path | None] = queue.Queue()
        results_queue: queue.Queue[tuple[Path, list[Any]]] = queue.Queue()
        worker = ScanWorker(work_queue, results_queue)

        parser = worker._get_parser(Path("/fake/main.go"))

        assert parser is not None
        assert isinstance(parser, GoParser)

    def test_get_parser_returns_rust_parser_for_rust_file(self) -> None:
        """Test that _get_parser returns RustParser for .rs files."""
        from hackmenot.parsers.rust import RustParser

        work_queue: queue.Queue[Path | None] = queue.Queue()
        results_queue: queue.Queue[tuple[Path, list[Any]]] = queue.Queue()
        worker = ScanWorker(work_queue, results_queue)

        parser = worker._get_parser(Path("/fake/lib.rs"))

        assert parser is not None
        assert isinstance(parser, RustParser)

    def test_get_parser_returns_java_parser_for_java_file(self) -> None:
        """Test that _get_parser returns JavaParser for .java files."""
        from hackmenot.parsers.java import JavaParser

        work_queue: queue.Queue[Path | None] = queue.Queue()
        results_queue: queue.Queue[tuple[Path, list[Any]]] = queue.Queue()
        worker = ScanWorker(work_queue, results_queue)

        parser = worker._get_parser(Path("/fake/App.java"))

        assert parser is not None
        assert isinstance(parser, JavaParser)

    def test_get_parser_returns_terraform_parser_for_tf_file(self) -> None:
        """Test that _get_parser returns TerraformParser for .tf files."""
        from hackmenot.parsers.terraform import TerraformParser

        work_queue: queue.Queue[Path | None] = queue.Queue()
        results_queue: queue.Queue[tuple[Path, list[Any]]] = queue.Queue()
        worker = ScanWorker(work_queue, results_queue)

        parser = worker._get_parser(Path("/fake/main.tf"))

        assert parser is not None
        assert isinstance(parser, TerraformParser)

    def test_get_parser_caches_parser_instances(self) -> None:
        """Test that _get_parser caches and reuses parser instances."""
        work_queue: queue.Queue[Path | None] = queue.Queue()
        results_queue: queue.Queue[tuple[Path, list[Any]]] = queue.Queue()
        worker = ScanWorker(work_queue, results_queue)

        # Get parser for first .py file
        parser1 = worker._get_parser(Path("/fake/test1.py"))
        # Get parser for second .py file
        parser2 = worker._get_parser(Path("/fake/test2.py"))

        # Should be the same instance (cached)
        assert parser1 is parser2

    def test_get_parser_creates_different_parsers_for_different_languages(self) -> None:
        """Test that different languages get different parser instances."""
        work_queue: queue.Queue[Path | None] = queue.Queue()
        results_queue: queue.Queue[tuple[Path, list[Any]]] = queue.Queue()
        worker = ScanWorker(work_queue, results_queue)

        # Get parsers for different languages
        py_parser = worker._get_parser(Path("/fake/test.py"))
        js_parser = worker._get_parser(Path("/fake/app.js"))
        go_parser = worker._get_parser(Path("/fake/main.go"))

        # All should be different instances
        assert py_parser is not None
        assert js_parser is not None
        assert go_parser is not None
        assert py_parser is not js_parser
        assert py_parser is not go_parser
        assert js_parser is not go_parser

    def test_get_parser_handles_all_js_extensions(self) -> None:
        """Test that _get_parser handles all JS/TS extensions."""
        from hackmenot.parsers.javascript import JavaScriptParser

        work_queue: queue.Queue[Path | None] = queue.Queue()
        results_queue: queue.Queue[tuple[Path, list[Any]]] = queue.Queue()
        worker = ScanWorker(work_queue, results_queue)

        extensions = [".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"]
        for ext in extensions:
            parser = worker._get_parser(Path(f"/fake/file{ext}"))
            assert parser is not None
            assert isinstance(parser, JavaScriptParser)

    def test_get_parser_handles_all_terraform_extensions(self) -> None:
        """Test that _get_parser handles all Terraform extensions."""
        from hackmenot.parsers.terraform import TerraformParser

        work_queue: queue.Queue[Path | None] = queue.Queue()
        results_queue: queue.Queue[tuple[Path, list[Any]]] = queue.Queue()
        worker = ScanWorker(work_queue, results_queue)

        extensions = [".tf", ".tfvars"]
        for ext in extensions:
            parser = worker._get_parser(Path(f"/fake/file{ext}"))
            assert parser is not None
            assert isinstance(parser, TerraformParser)

    def test_get_parser_returns_none_for_unsupported_extension(self) -> None:
        """Test that _get_parser returns None for unsupported file extensions."""
        work_queue: queue.Queue[Path | None] = queue.Queue()
        results_queue: queue.Queue[tuple[Path, list[Any]]] = queue.Queue()
        worker = ScanWorker(work_queue, results_queue)

        # Test various unsupported extensions
        unsupported = [".md", ".json", ".yaml", ".txt", ".exe", ""]
        for ext in unsupported:
            parser = worker._get_parser(Path(f"/fake/file{ext}"))
            assert parser is None

    def test_worker_initializes_with_empty_parser_cache(self) -> None:
        """Test that ScanWorker initializes with empty parser cache."""
        work_queue: queue.Queue[Path | None] = queue.Queue()
        results_queue: queue.Queue[tuple[Path, list[Any]]] = queue.Queue()
        worker = ScanWorker(work_queue, results_queue)

        # Worker should have an empty parsers dict
        assert hasattr(worker, "_parsers")
        assert isinstance(worker._parsers, dict)
        assert len(worker._parsers) == 0

    def test_parser_cache_is_per_worker(self) -> None:
        """Test that each worker has its own parser cache."""
        work_queue: queue.Queue[Path | None] = queue.Queue()
        results_queue: queue.Queue[tuple[Path, list[Any]]] = queue.Queue()

        worker1 = ScanWorker(work_queue, results_queue)
        worker2 = ScanWorker(work_queue, results_queue)

        # Get parsers in both workers
        parser1_py = worker1._get_parser(Path("/fake/test.py"))
        parser2_py = worker2._get_parser(Path("/fake/test.py"))

        # Should be different instances (not shared)
        assert parser1_py is not None
        assert parser2_py is not None
        assert parser1_py is not parser2_py
