"""Tests for file caching."""

from pathlib import Path

from hackmenot.core.cache import FileCache


def test_cache_stores_and_retrieves(tmp_path: Path):
    """Test cache stores and retrieves results."""
    cache_dir = tmp_path / ".hackmenot_cache"
    cache = FileCache(cache_dir)

    test_file = tmp_path / "test.py"
    test_file.write_text("print('hello')")

    findings = [{"rule_id": "TEST001", "line": 1}]

    cache.store(test_file, findings)
    result = cache.get(test_file)

    assert result == findings


def test_cache_invalidates_on_file_change(tmp_path: Path):
    """Test cache invalidates when file changes."""
    cache_dir = tmp_path / ".hackmenot_cache"
    cache = FileCache(cache_dir)

    test_file = tmp_path / "test.py"
    test_file.write_text("print('hello')")

    cache.store(test_file, [{"rule_id": "TEST001"}])

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
