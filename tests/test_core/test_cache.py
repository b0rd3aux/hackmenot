"""Tests for file caching."""

from pathlib import Path

from hackmenot.core.cache import FileCache
from hackmenot.core.models import Finding, Severity


def test_cache_stores_and_retrieves(tmp_path: Path):
    """Test cache stores and retrieves results."""
    cache_dir = tmp_path / ".hackmenot_cache"
    cache = FileCache(cache_dir)

    test_file = tmp_path / "test.py"
    test_file.write_text("print('hello')")

    findings = [
        Finding(
            rule_id="TEST001",
            rule_name="Test Rule",
            severity=Severity.LOW,
            message="Test message",
            file_path=str(test_file),
            line_number=1,
            column=0,
            code_snippet="print('hello')",
            fix_suggestion="",
            education="",
        )
    ]

    cache.store(test_file, findings)
    result = cache.get(test_file)

    assert result is not None
    assert len(result) == 1
    assert result[0].rule_id == "TEST001"


def test_cache_invalidates_on_file_change(tmp_path: Path):
    """Test cache invalidates when file changes."""
    cache_dir = tmp_path / ".hackmenot_cache"
    cache = FileCache(cache_dir)

    test_file = tmp_path / "test.py"
    test_file.write_text("print('hello')")

    findings = [
        Finding(
            rule_id="TEST001",
            rule_name="Test Rule",
            severity=Severity.LOW,
            message="Test message",
            file_path=str(test_file),
            line_number=1,
            column=0,
            code_snippet="print('hello')",
            fix_suggestion="",
            education="",
        )
    ]

    cache.store(test_file, findings)

    # Modify file
    test_file.write_text("print('world')")

    result = cache.get(test_file)
    assert result is None


def test_cache_returns_none_for_uncached(tmp_path: Path):
    """Test cache returns None for uncached files."""
    cache_dir = tmp_path / ".hackmenot_cache"
    cache = FileCache(cache_dir)

    test_file = tmp_path / "uncached.py"
    test_file.write_text("x = 1")

    result = cache.get(test_file)
    assert result is None
