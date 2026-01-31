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


class TestCacheVersioning:
    """Test cache versioning and rules hash invalidation."""

    def test_cache_invalidates_on_version_change(self, tmp_path: Path) -> None:
        """Cache should invalidate when CACHE_VERSION changes."""
        cache_dir = tmp_path / "cache"

        # Create a test file
        test_file = tmp_path / "test.py"
        test_file.write_text("password = 'secret'")

        # Store with current version
        cache = FileCache(cache_dir=cache_dir)
        findings = [
            Finding(
                rule_id="TEST001",
                rule_name="Test Rule",
                severity=Severity.HIGH,
                message="Test finding",
                file_path=str(test_file),
                line_number=1,
                column=0,
                code_snippet="password = 'secret'",
                fix_suggestion="",
                education="",
            )
        ]
        cache.store(test_file, findings)

        # Verify it's cached
        assert cache.get(test_file) is not None

        # Simulate version change by modifying CACHE_VERSION
        original_version = FileCache.CACHE_VERSION
        FileCache.CACHE_VERSION = "v999.0.0"

        try:
            # Create new cache instance - should not find old entry
            cache2 = FileCache(cache_dir=cache_dir)
            result = cache2.get(test_file)
            assert result is None  # Should be invalidated
        finally:
            FileCache.CACHE_VERSION = original_version

    def test_cache_invalidates_on_rules_hash_change(self, tmp_path: Path) -> None:
        """Cache should invalidate when rules hash changes."""
        cache_dir = tmp_path / "cache"
        test_file = tmp_path / "test.py"
        test_file.write_text("api_key = 'abc123'")

        # Store with one rules hash
        cache = FileCache(cache_dir=cache_dir, rules_hash="hash_v1")
        findings = [
            Finding(
                rule_id="TEST002",
                rule_name="Test",
                severity=Severity.MEDIUM,
                message="Test",
                file_path=str(test_file),
                line_number=1,
                column=0,
                code_snippet="api_key = 'abc123'",
                fix_suggestion="",
                education="",
            )
        ]
        cache.store(test_file, findings)
        assert cache.get(test_file) is not None

        # Create cache with different rules hash
        cache2 = FileCache(cache_dir=cache_dir, rules_hash="hash_v2")
        result = cache2.get(test_file)
        assert result is None  # Different rules = cache miss

    def test_cache_key_includes_version_and_rules(self, tmp_path: Path) -> None:
        """Cache key should include version and rules hash."""
        cache_dir = tmp_path / "cache"
        cache = FileCache(cache_dir=cache_dir, rules_hash="test_hash")

        # Check the cache file format includes version info
        test_file = tmp_path / "test.py"
        test_file.write_text("x = 1")
        cache.store(test_file, [])

        # Load the raw cache file and verify structure
        cache_file = cache_dir / "scan_cache.json"
        import json

        with open(cache_file) as f:
            data = json.load(f)

        # The metadata should include version and rules_hash
        assert "metadata" in data
        assert data["metadata"]["version"] == FileCache.CACHE_VERSION
        assert data["metadata"]["rules_hash"] == "test_hash"
