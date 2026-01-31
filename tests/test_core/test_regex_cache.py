"""Tests for regex caching."""

import re
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from hackmenot.core.regex_cache import RegexCache


class TestRegexCache:
    """Test the compiled regex cache."""

    def test_get_returns_compiled_pattern(self) -> None:
        """get() should return a compiled regex pattern."""
        cache = RegexCache()
        pattern = cache.get(r"\d+")

        assert isinstance(pattern, re.Pattern)
        assert pattern.search("abc123") is not None

    def test_get_caches_patterns(self) -> None:
        """Same pattern should return same compiled object."""
        cache = RegexCache()

        pattern1 = cache.get(r"test\d+")
        pattern2 = cache.get(r"test\d+")

        assert pattern1 is pattern2  # Same object reference

    def test_different_patterns_cached_separately(self) -> None:
        """Different patterns should be cached separately."""
        cache = RegexCache()

        pattern1 = cache.get(r"abc")
        pattern2 = cache.get(r"xyz")

        assert pattern1 is not pattern2
        assert pattern1.search("abc") is not None
        assert pattern2.search("xyz") is not None

    def test_get_with_flags(self) -> None:
        """get() should support regex flags."""
        cache = RegexCache()

        pattern = cache.get(r"test", flags=re.IGNORECASE)

        assert pattern.search("TEST") is not None
        assert pattern.search("test") is not None

    def test_same_pattern_different_flags_cached_separately(self) -> None:
        """Same pattern with different flags should be cached separately."""
        cache = RegexCache()

        pattern1 = cache.get(r"test", flags=0)
        pattern2 = cache.get(r"test", flags=re.IGNORECASE)

        assert pattern1 is not pattern2

    def test_thread_safety(self) -> None:
        """Cache should be thread-safe."""
        cache = RegexCache()
        results: list[re.Pattern] = []
        errors: list[Exception] = []

        def get_pattern() -> None:
            try:
                pattern = cache.get(r"thread_test\d+")
                results.append(pattern)
            except Exception as e:
                errors.append(e)

        # Run many concurrent accesses
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(get_pattern) for _ in range(100)]
            for future in futures:
                future.result()

        assert len(errors) == 0
        assert len(results) == 100
        # All should be the same object
        assert all(r is results[0] for r in results)

    def test_invalid_regex_raises_error(self) -> None:
        """Invalid regex should raise re.error."""
        cache = RegexCache()

        with pytest.raises(re.error):
            cache.get(r"[invalid")

    def test_clear_empties_cache(self) -> None:
        """clear() should empty the internal cache dictionary."""
        cache = RegexCache()

        # Add a pattern to the cache
        cache.get(r"test_clear_pattern")

        # Verify internal cache has the entry
        assert len(cache._cache) == 1

        # Clear the cache
        cache.clear()

        # Verify internal cache is empty
        assert len(cache._cache) == 0

        # Pattern can still be retrieved (re-compiled)
        pattern = cache.get(r"test_clear_pattern")
        assert pattern.search("test_clear_pattern") is not None
        assert len(cache._cache) == 1
