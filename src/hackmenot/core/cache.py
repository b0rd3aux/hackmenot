"""File caching for incremental scans."""

import hashlib
import json
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

    def get(self, file_path: Path) -> list[Finding] | None:
        """Get cached results for a file, or None if not cached/stale."""
        key = str(file_path.absolute())

        if key not in self._cache:
            return None

        stored_hash, findings_data = self._cache[key]
        current_hash = self._file_hash(file_path)

        if stored_hash != current_hash:
            # File changed, invalidate cache
            del self._cache[key]
            return None

        # Deserialize findings from dict format
        if findings_data and isinstance(findings_data[0], dict):
            return _deserialize_findings(findings_data)
        return findings_data

    def store(self, file_path: Path, findings: list[Finding]) -> None:
        """Store results for a file."""
        key = str(file_path.absolute())
        file_hash = self._file_hash(file_path)
        # Serialize findings to dict format for JSON storage
        serialized = _serialize_findings(findings) if findings else []
        self._cache[key] = (file_hash, serialized)
        self._save_cache()

    def clear(self) -> None:
        """Clear all cached results."""
        self._cache = {}
        cache_file = self.cache_dir / "scan_cache.json"
        if cache_file.exists():
            cache_file.unlink()
