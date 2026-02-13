"""Tests for ParallelScanner class."""

import os

from hackmenot.core.parallel_scanner import ParallelScanner


class TestParallelScannerInit:
    """Test ParallelScanner initialization."""

    def test_default_worker_count(self):
        """Test that ParallelScanner defaults to cpu_count() workers."""
        scanner = ParallelScanner()
        expected_workers = os.cpu_count()
        assert scanner.num_workers == expected_workers

    def test_custom_worker_count(self):
        """Test that ParallelScanner accepts custom worker count."""
        custom_count = 4
        scanner = ParallelScanner(num_workers=custom_count)
        assert scanner.num_workers == custom_count

    def test_explicit_none_uses_default(self):
        """Test that explicitly passing None uses default cpu_count()."""
        scanner = ParallelScanner(num_workers=None)
        expected_workers = os.cpu_count()
        assert scanner.num_workers == expected_workers
