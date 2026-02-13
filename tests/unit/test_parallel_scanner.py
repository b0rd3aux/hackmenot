"""Tests for ParallelScanner class."""

from hackmenot.core.constants import DEFAULT_WORKERS
from hackmenot.core.parallel_scanner import ParallelScanner


class TestParallelScannerInit:
    """Test ParallelScanner initialization."""

    def test_default_worker_count(self):
        """Test that ParallelScanner defaults to DEFAULT_WORKERS."""
        scanner = ParallelScanner()
        assert scanner.num_workers == DEFAULT_WORKERS

    def test_custom_worker_count(self):
        """Test that ParallelScanner accepts custom worker count."""
        custom_count = 4
        scanner = ParallelScanner(num_workers=custom_count)
        assert scanner.num_workers == custom_count

    def test_explicit_none_uses_default(self):
        """Test that explicitly passing None uses DEFAULT_WORKERS."""
        scanner = ParallelScanner(num_workers=None)
        assert scanner.num_workers == DEFAULT_WORKERS
