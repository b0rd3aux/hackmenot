"""File caching for incremental scans."""

import hashlib
import json
import threading
from pathlib import Path
from typing import Any

from hackmenot.core.models import Finding, Severity


def _serialize_findings(findings: list[Finding]) -> list[dict[str, Any]]:
    """Convert Finding objects to JSON-compatible dicts."""
    return [
        {
            "rule_id": f.rule_id,
            "rule_name": f.rule_name,
            "severity": f.severity.value,
            "message": f.message,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "column": f.column,
            "code_snippet": f.code_snippet,
            "fix_suggestion": f.fix_suggestion,
            "education": f.education,
            "context_before": f.context_before,
            "context_after": f.context_after,
        }
        for f in findings
    ]


def _deserialize_findings(data: list[dict[str, Any]]) -> list[Finding]:
    """Restore Finding objects from dicts."""
    return [
        Finding(
            rule_id=d["rule_id"],
            rule_name=d["rule_name"],
            severity=Severity(d["severity"]),
            message=d["message"],
            file_path=d["file_path"],
            line_number=d["line_number"],
            column=d["column"],
            code_snippet=d["code_snippet"],
            fix_suggestion=d["fix_suggestion"],
            education=d["education"],
            context_before=d.get("context_before", []),
            context_after=d.get("context_after", []),
        )
        for d in data
    ]


class FileCache:
    """Cache for storing scan results by file hash.

    Thread-safe: uses a lock to protect concurrent access.
    """

    CACHE_VERSION = "v1.0.0"

    def __init__(
        self, cache_dir: Path | None = None, rules_hash: str | None = None
    ) -> None:
        self.cache_dir = cache_dir or self._default_cache_dir()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.rules_hash = rules_hash or ""
        self._cache: dict[str, tuple[str, list[dict[str, Any]]]] = {}
        self._lock = threading.Lock()
        self._load_cache()

    def _default_cache_dir(self) -> Path:
        """Get default cache directory."""
        return Path.home() / ".hackmenot" / "cache"

    def _load_cache(self) -> None:
        """Load cache from disk, validating version and rules hash."""
        cache_file = self.cache_dir / "scan_cache.json"
        if cache_file.exists():
            try:
                with open(cache_file) as f:
                    data = json.load(f)

                # Check metadata for version and rules compatibility
                metadata = data.get("metadata", {})
                stored_version = metadata.get("version", "")
                stored_rules_hash = metadata.get("rules_hash", "")

                if stored_version != self.CACHE_VERSION:
                    # Version mismatch - invalidate entire cache
                    self._cache = {}
                    return

                if stored_rules_hash != self.rules_hash:
                    # Rules changed - invalidate entire cache
                    self._cache = {}
                    return

                # Load the entries
                entries = data.get("entries", {})
                self._cache = {k: (v[0], v[1]) for k, v in entries.items()}
            except (json.JSONDecodeError, OSError, KeyError, IndexError):
                self._cache = {}

    def _save_cache(self) -> None:
        """Save cache to disk with version metadata."""
        cache_file = self.cache_dir / "scan_cache.json"
        try:
            data = {
                "metadata": {
                    "version": self.CACHE_VERSION,
                    "rules_hash": self.rules_hash,
                },
                "entries": {k: list(v) for k, v in self._cache.items()},
            }
            with open(cache_file, "w") as f:
                json.dump(data, f)
        except OSError:
            pass  # Fail silently for cache writes

    def _file_hash(self, file_path: Path) -> str:
        """Compute hash of file contents."""
        content = file_path.read_bytes()
        return hashlib.sha256(content).hexdigest()

    def get(self, file_path: Path) -> list[Finding] | None:
        """Get cached results for a file, or None if not cached/stale.

        Thread-safe: protected by lock.
        """
        key = str(file_path.absolute())
        current_hash = self._file_hash(file_path)

        with self._lock:
            if key not in self._cache:
                return None

            stored_hash, findings_data = self._cache[key]

            if stored_hash != current_hash:
                # File changed, invalidate cache
                del self._cache[key]
                return None

            # Deserialize findings from dict format
            return _deserialize_findings(findings_data)

    def store(self, file_path: Path, findings: list[Finding]) -> None:
        """Store results for a file.

        Thread-safe: protected by lock.
        """
        key = str(file_path.absolute())
        file_hash = self._file_hash(file_path)
        # Serialize findings to dict format for JSON storage
        serialized = _serialize_findings(findings) if findings else []

        with self._lock:
            self._cache[key] = (file_hash, serialized)
            self._save_cache()

    def clear(self) -> None:
        """Clear all cached results."""
        self._cache = {}
        cache_file = self.cache_dir / "scan_cache.json"
        if cache_file.exists():
            cache_file.unlink()
