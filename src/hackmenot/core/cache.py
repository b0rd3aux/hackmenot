"""File caching for incremental scans."""

import hashlib
import json
from pathlib import Path
from typing import Any


class FileCache:
    """Cache for storing scan results by file hash."""

    def __init__(self, cache_dir: Path | None = None) -> None:
        self.cache_dir = cache_dir or self._default_cache_dir()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, tuple[str, Any]] = {}
        self._load_cache()

    def _default_cache_dir(self) -> Path:
        """Get default cache directory."""
        return Path.home() / ".hackmenot" / "cache"

    def _load_cache(self) -> None:
        """Load cache from disk."""
        cache_file = self.cache_dir / "scan_cache.json"
        if cache_file.exists():
            try:
                with open(cache_file) as f:
                    data = json.load(f)
                    self._cache = {k: tuple(v) for k, v in data.items()}
            except Exception:
                self._cache = {}

    def _save_cache(self) -> None:
        """Save cache to disk."""
        cache_file = self.cache_dir / "scan_cache.json"
        try:
            with open(cache_file, "w") as f:
                json.dump({k: list(v) for k, v in self._cache.items()}, f)
        except Exception:
            pass  # Fail silently for cache writes

    def _file_hash(self, file_path: Path) -> str:
        """Compute hash of file contents."""
        content = file_path.read_bytes()
        return hashlib.sha256(content).hexdigest()

    def get(self, file_path: Path) -> Any | None:
        """Get cached results for a file, or None if not cached/stale."""
        key = str(file_path.absolute())

        if key not in self._cache:
            return None

        stored_hash, findings = self._cache[key]
        current_hash = self._file_hash(file_path)

        if stored_hash != current_hash:
            # File changed, invalidate cache
            del self._cache[key]
            return None

        return findings

    def store(self, file_path: Path, findings: Any) -> None:
        """Store results for a file."""
        key = str(file_path.absolute())
        file_hash = self._file_hash(file_path)
        self._cache[key] = (file_hash, findings)
        self._save_cache()

    def clear(self) -> None:
        """Clear all cached results."""
        self._cache = {}
        cache_file = self.cache_dir / "scan_cache.json"
        if cache_file.exists():
            cache_file.unlink()
