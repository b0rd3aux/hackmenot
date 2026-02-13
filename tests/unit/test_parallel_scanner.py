"""Tests for ParallelScanner class."""

import multiprocessing
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

    def test_initializes_work_queue_with_maxsize(self) -> None:
        """Test that work_queue is initialized with maxsize=1000."""
        scanner = ParallelScanner()
        assert isinstance(scanner.work_queue, multiprocessing.queues.Queue)
        # Note: multiprocessing.Queue doesn't expose maxsize directly,
        # but we can verify it's bounded by trying to fill it
        assert scanner.work_queue._maxsize == 1000

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
