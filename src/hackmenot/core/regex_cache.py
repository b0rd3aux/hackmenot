"""Thread-safe compiled regex pattern cache."""

import re
import threading
from typing import Pattern


class RegexCache:
    """Thread-safe cache for compiled regex patterns.

    Uses a simple dictionary with LRU eviction for efficient caching.
    Thread-safe for concurrent pattern retrieval.
    """

    def __init__(self, maxsize: int = 256) -> None:
        """Initialize the regex cache.

        Args:
            maxsize: Maximum number of patterns to cache (default 256).
        """
        self._lock = threading.Lock()
        self._maxsize = maxsize
        self._cache: dict[tuple[str, int], Pattern[str]] = {}

    def get(self, pattern: str, flags: int = 0) -> Pattern[str]:
        """Get a compiled regex pattern, using cache if available.

        Thread-safe: uses lock for concurrent access.

        Args:
            pattern: The regex pattern string.
            flags: Regex flags (re.IGNORECASE, etc.).

        Returns:
            Compiled regex pattern.

        Raises:
            re.error: If the pattern is invalid.
        """
        key = (pattern, flags)
        with self._lock:
            if key not in self._cache:
                # LRU eviction: remove oldest if at max size
                if len(self._cache) >= self._maxsize:
                    # Remove first (oldest) item
                    oldest_key = next(iter(self._cache))
                    del self._cache[oldest_key]
                self._cache[key] = re.compile(pattern, flags)
            return self._cache[key]

    def clear(self) -> None:
        """Clear all cached patterns."""
        with self._lock:
            self._cache.clear()
