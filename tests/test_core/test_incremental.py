"""Tests for incremental scanning with cache integration."""

from pathlib import Path
from unittest.mock import patch

from hackmenot.core.cache import FileCache
from hackmenot.core.models import Finding, Severity
from hackmenot.core.scanner import Scanner


def test_scanner_uses_cache(tmp_path: Path):
    """Test scanner uses cached findings for unchanged files."""
    cache_dir = tmp_path / ".hackmenot_cache"
    cache = FileCache(cache_dir)

    # Create a test file with a vulnerability
    test_file = tmp_path / "vuln.py"
    test_file.write_text('query = f"SELECT * FROM users WHERE id = {x}"\n')

    scanner = Scanner(cache=cache)

    # First scan - should actually scan the file
    result1 = scanner.scan([tmp_path], use_cache=True)
    assert result1.files_scanned == 1
    findings_count = len(result1.findings)
    assert findings_count > 0  # Should find the SQL injection

    # Second scan - should use cache (file unchanged)
    with patch.object(scanner, "_scan_file", wraps=scanner._scan_file) as mock_scan:
        result2 = scanner.scan([tmp_path], use_cache=True)
        # _scan_file should not be called since we use cache
        mock_scan.assert_not_called()

    # Should return same findings from cache
    assert len(result2.findings) == findings_count


def test_scanner_invalidates_cache_on_change(tmp_path: Path):
    """Test scanner invalidates cache when file changes."""
    cache_dir = tmp_path / ".hackmenot_cache"
    cache = FileCache(cache_dir)

    # Create a test file with a vulnerability
    test_file = tmp_path / "vuln.py"
    test_file.write_text('query = f"SELECT * FROM users WHERE id = {x}"\n')

    scanner = Scanner(cache=cache)

    # First scan
    result1 = scanner.scan([tmp_path], use_cache=True)
    assert result1.has_findings

    # Modify the file to remove the vulnerability
    test_file.write_text('query = "SELECT * FROM users WHERE id = ?"\n')

    # Second scan - should re-scan due to file change
    with patch.object(scanner, "_scan_file", wraps=scanner._scan_file) as mock_scan:
        result2 = scanner.scan([tmp_path], use_cache=True)
        # _scan_file should be called since file changed
        mock_scan.assert_called_once()

    # Should have no findings now (safe query)
    assert not result2.has_findings


def test_scanner_full_flag_bypasses_cache(tmp_path: Path):
    """Test use_cache=False bypasses cache."""
    cache_dir = tmp_path / ".hackmenot_cache"
    cache = FileCache(cache_dir)

    # Create a test file
    test_file = tmp_path / "test.py"
    test_file.write_text('print("hello")\n')

    scanner = Scanner(cache=cache)

    # First scan with cache
    scanner.scan([tmp_path], use_cache=True)

    # Second scan with use_cache=False - should bypass cache
    with patch.object(scanner, "_scan_file", wraps=scanner._scan_file) as mock_scan:
        scanner.scan([tmp_path], use_cache=False)
        # _scan_file should be called even though file is cached
        mock_scan.assert_called_once()


def test_scanner_without_cache_works(tmp_path: Path):
    """Test scanner works without cache (backward compatibility)."""
    test_file = tmp_path / "test.py"
    test_file.write_text('print("hello")\n')

    # Scanner without cache should still work
    scanner = Scanner()
    result = scanner.scan([tmp_path])

    assert result.files_scanned == 1


def test_cache_serializes_findings(tmp_path: Path):
    """Test that Finding objects are properly serialized and deserialized."""
    cache_dir = tmp_path / ".hackmenot_cache"
    cache = FileCache(cache_dir)

    test_file = tmp_path / "test.py"
    test_file.write_text('x = 1\n')

    findings = [
        Finding(
            rule_id="TEST001",
            rule_name="Test Rule",
            severity=Severity.HIGH,
            message="Test message",
            file_path=str(test_file),
            line_number=1,
            column=0,
            code_snippet="x = 1",
            fix_suggestion="Fix it",
            education="Learn more",
            context_before=["# before"],
            context_after=["# after"],
        )
    ]

    cache.store(test_file, findings)

    # Create new cache instance to ensure we read from disk
    cache2 = FileCache(cache_dir)
    retrieved = cache2.get(test_file)

    assert retrieved is not None
    assert len(retrieved) == 1
    assert isinstance(retrieved[0], Finding)
    assert retrieved[0].rule_id == "TEST001"
    assert retrieved[0].severity == Severity.HIGH
    assert retrieved[0].context_before == ["# before"]
    assert retrieved[0].context_after == ["# after"]
