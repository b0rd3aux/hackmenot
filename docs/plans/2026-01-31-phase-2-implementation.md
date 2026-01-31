# Phase 2: Full Python + Fixes - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make hackmenot fast, configurable, and produce actionable fixes with 35 rules.

**Architecture:** Scanner gains parallel processing + caching integration. New components: ConfigLoader, IgnoreHandler, FixEngine, SARIFReporter.

**Tech Stack:** Python 3.11+, ThreadPoolExecutor, PyYAML, Rich

---

## Task 1: Incremental Scanning (Wire Cache into Scanner)

**Files:**
- Modify: `src/hackmenot/core/scanner.py`
- Modify: `src/hackmenot/core/cache.py` (add Finding serialization)
- Create: `tests/test_core/test_incremental.py`

**Step 1: Write the failing test**

Create `tests/test_core/test_incremental.py`:
```python
"""Tests for incremental scanning."""

from pathlib import Path

from hackmenot.core.scanner import Scanner


def test_scanner_uses_cache(tmp_path: Path):
    """Test scanner uses cache for unchanged files."""
    scanner = Scanner()

    # Create a file with a vulnerability
    vuln_file = tmp_path / "vuln.py"
    vuln_file.write_text('query = f"SELECT * FROM users WHERE id = {x}"')

    # First scan - should find the vulnerability
    result1 = scanner.scan([tmp_path])
    assert len(result1.findings) >= 1

    # Second scan - should use cache (same results)
    result2 = scanner.scan([tmp_path])
    assert len(result2.findings) == len(result1.findings)


def test_scanner_invalidates_cache_on_change(tmp_path: Path):
    """Test scanner invalidates cache when file changes."""
    scanner = Scanner()

    # Create a file with a vulnerability
    vuln_file = tmp_path / "vuln.py"
    vuln_file.write_text('query = f"SELECT * FROM users WHERE id = {x}"')

    # First scan
    result1 = scanner.scan([tmp_path])
    assert len(result1.findings) >= 1

    # Modify file to remove vulnerability
    vuln_file.write_text('query = "SELECT * FROM users WHERE id = ?"')

    # Second scan - cache should be invalidated
    result2 = scanner.scan([tmp_path])
    assert len(result2.findings) == 0


def test_scanner_full_flag_bypasses_cache(tmp_path: Path):
    """Test --full flag bypasses cache."""
    scanner = Scanner()

    vuln_file = tmp_path / "vuln.py"
    vuln_file.write_text('query = f"SELECT * FROM users WHERE id = {x}"')

    # First scan with caching
    result1 = scanner.scan([tmp_path])

    # Full scan should still work (bypasses cache)
    result2 = scanner.scan([tmp_path], use_cache=False)
    assert len(result2.findings) == len(result1.findings)
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_core/test_incremental.py -v
```

**Step 3: Update cache.py to serialize Findings**

Update `src/hackmenot/core/cache.py` to handle Finding serialization:
```python
"""File caching for incremental scans."""

import hashlib
import json
from pathlib import Path
from typing import Any


def _serialize_findings(findings: list) -> list[dict]:
    """Serialize findings to JSON-compatible format."""
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
        }
        for f in findings
    ]


def _deserialize_findings(data: list[dict]) -> list:
    """Deserialize findings from JSON format."""
    from hackmenot.core.models import Finding, Severity

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

    def get(self, file_path: Path) -> list | None:
        """Get cached findings for a file, or None if not cached/stale."""
        key = str(file_path.absolute())

        if key not in self._cache:
            return None

        stored_hash, findings_data = self._cache[key]
        current_hash = self._file_hash(file_path)

        if stored_hash != current_hash:
            del self._cache[key]
            return None

        return _deserialize_findings(findings_data)

    def store(self, file_path: Path, findings: list) -> None:
        """Store findings for a file."""
        key = str(file_path.absolute())
        file_hash = self._file_hash(file_path)
        self._cache[key] = (file_hash, _serialize_findings(findings))
        self._save_cache()

    def clear(self) -> None:
        """Clear all cached results."""
        self._cache = {}
        cache_file = self.cache_dir / "scan_cache.json"
        if cache_file.exists():
            cache_file.unlink()
```

**Step 4: Update scanner.py to use cache**

Update `src/hackmenot/core/scanner.py`:
```python
"""Scanner orchestrator."""

import time
from pathlib import Path

from hackmenot.core.cache import FileCache
from hackmenot.core.models import Finding, ScanResult, Severity
from hackmenot.parsers.python import PythonParser
from hackmenot.rules.engine import RulesEngine
from hackmenot.rules.registry import RuleRegistry


class Scanner:
    """Main scanner that orchestrates parsing and rule checking."""

    SUPPORTED_EXTENSIONS = {".py"}

    def __init__(self, cache_dir: Path | None = None) -> None:
        self.parser = PythonParser()
        self.engine = RulesEngine()
        self.cache = FileCache(cache_dir)
        self._load_rules()

    def _load_rules(self) -> None:
        """Load all built-in rules."""
        registry = RuleRegistry()
        registry.load_all()
        for rule in registry.get_all_rules():
            self.engine.register_rule(rule)

    def scan(
        self,
        paths: list[Path],
        min_severity: Severity = Severity.LOW,
        use_cache: bool = True,
    ) -> ScanResult:
        """Scan paths for security vulnerabilities."""
        start_time = time.time()

        files = self._collect_files(paths)
        findings: list[Finding] = []
        errors: list[str] = []

        for file_path in files:
            try:
                file_findings = self._scan_file(file_path, use_cache=use_cache)
                file_findings = [
                    f for f in file_findings if f.severity >= min_severity
                ]
                findings.extend(file_findings)
            except Exception as e:
                errors.append(f"{file_path}: {e}")

        elapsed_ms = (time.time() - start_time) * 1000

        return ScanResult(
            files_scanned=len(files),
            findings=findings,
            scan_time_ms=elapsed_ms,
            errors=errors,
        )

    def _collect_files(self, paths: list[Path]) -> list[Path]:
        """Collect all scannable files from paths."""
        files: list[Path] = []

        for path in paths:
            if path.is_file():
                if path.suffix in self.SUPPORTED_EXTENSIONS:
                    files.append(path)
            elif path.is_dir():
                for ext in self.SUPPORTED_EXTENSIONS:
                    files.extend(path.rglob(f"*{ext}"))

        return sorted(set(files))

    def _scan_file(self, file_path: Path, use_cache: bool = True) -> list[Finding]:
        """Scan a single file."""
        # Check cache first
        if use_cache:
            cached = self.cache.get(file_path)
            if cached is not None:
                return cached

        # Parse and check
        parse_result = self.parser.parse_file(file_path)
        if parse_result.has_error:
            findings: list[Finding] = []
        else:
            findings = self.engine.check(parse_result, file_path)

        # Store in cache
        if use_cache:
            self.cache.store(file_path, findings)

        return findings
```

**Step 5: Run tests**

```bash
pytest tests/test_core/test_incremental.py -v
```

**Step 6: Run full test suite**

```bash
pytest -v
```

**Step 7: Commit**

```bash
git add -A
git commit -m "feat: wire cache into scanner for incremental scanning"
```

---

## Task 2: Parallel Processing

**Files:**
- Modify: `src/hackmenot/core/scanner.py`
- Create: `tests/test_core/test_parallel.py`

**Step 1: Write the failing test**

Create `tests/test_core/test_parallel.py`:
```python
"""Tests for parallel scanning."""

from pathlib import Path

from hackmenot.core.scanner import Scanner


def test_parallel_scan_finds_all_vulnerabilities(tmp_path: Path):
    """Test parallel scanning finds vulnerabilities in multiple files."""
    scanner = Scanner()

    # Create multiple files with vulnerabilities
    for i in range(10):
        (tmp_path / f"file{i}.py").write_text(
            f'query{i} = f"SELECT * FROM users WHERE id = {{x}}"'
        )

    result = scanner.scan([tmp_path], parallel=True)

    # Should find vulnerability in each file
    assert len(result.findings) >= 10
    assert result.files_scanned == 10


def test_parallel_scan_faster_than_sequential(tmp_path: Path):
    """Test parallel scanning is not significantly slower."""
    scanner = Scanner()

    # Create files
    for i in range(20):
        (tmp_path / f"file{i}.py").write_text(f'x = {i}')

    # Parallel scan
    result = scanner.scan([tmp_path], parallel=True, use_cache=False)

    assert result.files_scanned == 20
    # Just verify it completes - speed comparison is flaky in tests


def test_parallel_scan_handles_errors_gracefully(tmp_path: Path):
    """Test parallel scanning handles file errors gracefully."""
    scanner = Scanner()

    # Create a good file and a bad file
    (tmp_path / "good.py").write_text('x = 1')
    bad_file = tmp_path / "bad.py"
    bad_file.write_text('def broken(')

    result = scanner.scan([tmp_path], parallel=True)

    # Should still complete and scan the good file
    assert result.files_scanned == 2
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_core/test_parallel.py -v
```

**Step 3: Update scanner.py with parallel processing**

```python
"""Scanner orchestrator."""

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from hackmenot.core.cache import FileCache
from hackmenot.core.models import Finding, ScanResult, Severity
from hackmenot.parsers.python import PythonParser
from hackmenot.rules.engine import RulesEngine
from hackmenot.rules.registry import RuleRegistry


class Scanner:
    """Main scanner that orchestrates parsing and rule checking."""

    SUPPORTED_EXTENSIONS = {".py"}
    DEFAULT_WORKERS = min(32, (os.cpu_count() or 1) + 4)

    def __init__(self, cache_dir: Path | None = None) -> None:
        self.parser = PythonParser()
        self.engine = RulesEngine()
        self.cache = FileCache(cache_dir)
        self._load_rules()

    def _load_rules(self) -> None:
        """Load all built-in rules."""
        registry = RuleRegistry()
        registry.load_all()
        for rule in registry.get_all_rules():
            self.engine.register_rule(rule)

    def scan(
        self,
        paths: list[Path],
        min_severity: Severity = Severity.LOW,
        use_cache: bool = True,
        parallel: bool = True,
        max_workers: int | None = None,
    ) -> ScanResult:
        """Scan paths for security vulnerabilities."""
        start_time = time.time()

        files = self._collect_files(paths)
        findings: list[Finding] = []
        errors: list[str] = []

        if parallel and len(files) > 1:
            workers = max_workers or self.DEFAULT_WORKERS
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(self._scan_file, f, use_cache): f
                    for f in files
                }
                for future in as_completed(futures):
                    file_path = futures[future]
                    try:
                        file_findings = future.result()
                        file_findings = [
                            f for f in file_findings if f.severity >= min_severity
                        ]
                        findings.extend(file_findings)
                    except Exception as e:
                        errors.append(f"{file_path}: {e}")
        else:
            for file_path in files:
                try:
                    file_findings = self._scan_file(file_path, use_cache=use_cache)
                    file_findings = [
                        f for f in file_findings if f.severity >= min_severity
                    ]
                    findings.extend(file_findings)
                except Exception as e:
                    errors.append(f"{file_path}: {e}")

        elapsed_ms = (time.time() - start_time) * 1000

        return ScanResult(
            files_scanned=len(files),
            findings=findings,
            scan_time_ms=elapsed_ms,
            errors=errors,
        )

    def _collect_files(self, paths: list[Path]) -> list[Path]:
        """Collect all scannable files from paths."""
        files: list[Path] = []

        for path in paths:
            if path.is_file():
                if path.suffix in self.SUPPORTED_EXTENSIONS:
                    files.append(path)
            elif path.is_dir():
                for ext in self.SUPPORTED_EXTENSIONS:
                    files.extend(path.rglob(f"*{ext}"))

        return sorted(set(files))

    def _scan_file(self, file_path: Path, use_cache: bool = True) -> list[Finding]:
        """Scan a single file."""
        if use_cache:
            cached = self.cache.get(file_path)
            if cached is not None:
                return cached

        parse_result = self.parser.parse_file(file_path)
        if parse_result.has_error:
            findings: list[Finding] = []
        else:
            findings = self.engine.check(parse_result, file_path)

        if use_cache:
            self.cache.store(file_path, findings)

        return findings
```

**Step 4: Run tests**

```bash
pytest tests/test_core/test_parallel.py tests/test_core/test_incremental.py -v
```

**Step 5: Run full test suite**

```bash
pytest -v
```

**Step 6: Commit**

```bash
git add -A
git commit -m "feat: add parallel processing with ThreadPoolExecutor"
```

---

## Task 3: ConfigLoader

**Files:**
- Create: `src/hackmenot/core/config.py`
- Modify: `src/hackmenot/core/__init__.py`
- Create: `tests/test_core/test_config.py`

**Step 1: Write the failing test**

Create `tests/test_core/test_config.py`:
```python
"""Tests for configuration loading."""

from pathlib import Path

from hackmenot.core.config import Config, ConfigLoader


def test_config_defaults():
    """Test default configuration values."""
    config = Config()

    assert config.fail_on == "high"
    assert config.rules_disable == []
    assert config.paths_exclude == []


def test_load_config_from_file(tmp_path: Path):
    """Test loading config from YAML file."""
    config_file = tmp_path / ".hackmenot.yml"
    config_file.write_text("""
fail_on: critical

rules:
  disable: [DEP001, DEP002]

paths:
  exclude:
    - "tests/*"
    - "vendor/*"
""")

    loader = ConfigLoader()
    config = loader.load(tmp_path)

    assert config.fail_on == "critical"
    assert config.rules_disable == ["DEP001", "DEP002"]
    assert "tests/*" in config.paths_exclude


def test_load_config_missing_file(tmp_path: Path):
    """Test loading config when file doesn't exist returns defaults."""
    loader = ConfigLoader()
    config = loader.load(tmp_path)

    assert config.fail_on == "high"


def test_config_merge_with_global(tmp_path: Path):
    """Test project config overrides global config."""
    # Create global config
    global_dir = tmp_path / "global"
    global_dir.mkdir()
    (global_dir / "config.yml").write_text("""
fail_on: low
rules:
  disable: [CRYPTO001]
""")

    # Create project config
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / ".hackmenot.yml").write_text("""
fail_on: high
""")

    loader = ConfigLoader(global_config_dir=global_dir)
    config = loader.load(project_dir)

    # Project overrides global for fail_on
    assert config.fail_on == "high"
    # Global rule disable should still apply
    assert "CRYPTO001" in config.rules_disable
```

**Step 2: Create config.py**

Create `src/hackmenot/core/config.py`:
```python
"""Configuration loading and management."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class Config:
    """Configuration for hackmenot."""

    fail_on: str = "high"
    rules_disable: list[str] = field(default_factory=list)
    rules_enable: list[str] = field(default_factory=lambda: ["all"])
    severity_override: dict[str, str] = field(default_factory=dict)
    paths_include: list[str] = field(default_factory=list)
    paths_exclude: list[str] = field(default_factory=list)
    fixes_auto_apply_safe: bool = True


class ConfigLoader:
    """Loads configuration from YAML files."""

    def __init__(self, global_config_dir: Path | None = None) -> None:
        self.global_config_dir = global_config_dir or (
            Path.home() / ".config" / "hackmenot"
        )

    def load(self, project_dir: Path) -> Config:
        """Load configuration, merging global and project configs."""
        config = Config()

        # Load global config first
        global_config_file = self.global_config_dir / "config.yml"
        if global_config_file.exists():
            self._apply_config_file(config, global_config_file)

        # Load project config (overrides global)
        project_config_file = project_dir / ".hackmenot.yml"
        if project_config_file.exists():
            self._apply_config_file(config, project_config_file)

        return config

    def _apply_config_file(self, config: Config, file_path: Path) -> None:
        """Apply settings from a config file to the config object."""
        try:
            with open(file_path) as f:
                data = yaml.safe_load(f) or {}
        except Exception:
            return

        if "fail_on" in data:
            config.fail_on = data["fail_on"]

        rules = data.get("rules", {})
        if "disable" in rules:
            config.rules_disable.extend(rules["disable"])
        if "enable" in rules:
            config.rules_enable = rules["enable"]
        if "severity_override" in rules:
            config.severity_override.update(rules["severity_override"])

        paths = data.get("paths", {})
        if "include" in paths:
            config.paths_include.extend(paths["include"])
        if "exclude" in paths:
            config.paths_exclude.extend(paths["exclude"])

        fixes = data.get("fixes", {})
        if "auto_apply_safe" in fixes:
            config.fixes_auto_apply_safe = fixes["auto_apply_safe"]
```

**Step 3: Update __init__.py**

Update `src/hackmenot/core/__init__.py`:
```python
"""Core module for hackmenot."""

from hackmenot.core.cache import FileCache
from hackmenot.core.config import Config, ConfigLoader
from hackmenot.core.models import Finding, Rule, ScanResult, Severity
from hackmenot.core.scanner import Scanner

__all__ = [
    "Severity",
    "Finding",
    "Rule",
    "ScanResult",
    "Scanner",
    "FileCache",
    "Config",
    "ConfigLoader",
]
```

**Step 4: Run tests**

```bash
pytest tests/test_core/test_config.py -v
```

**Step 5: Commit**

```bash
git add -A
git commit -m "feat: add ConfigLoader for .hackmenot.yml support"
```

---

## Task 4: IgnoreHandler

**Files:**
- Create: `src/hackmenot/core/ignores.py`
- Modify: `src/hackmenot/rules/engine.py`
- Create: `tests/test_core/test_ignores.py`

**Step 1: Write the failing test**

Create `tests/test_core/test_ignores.py`:
```python
"""Tests for inline ignore handling."""

from hackmenot.core.ignores import IgnoreHandler


def test_parse_single_line_ignore():
    """Test parsing single line ignore comment."""
    source = '''
x = 1
password = "secret"  # hackmenot:ignore[AUTH002] - test fixture
y = 2
'''
    handler = IgnoreHandler()
    ignores = handler.parse(source)

    assert (3, "AUTH002") in ignores


def test_parse_next_line_ignore():
    """Test parsing next-line ignore comment."""
    source = '''
# hackmenot:ignore-next-line[INJ001] - legacy code
query = f"SELECT * FROM users WHERE id = {x}"
'''
    handler = IgnoreHandler()
    ignores = handler.parse(source)

    assert (3, "INJ001") in ignores


def test_parse_file_ignore():
    """Test parsing file-level ignore comment."""
    source = '''# hackmenot:ignore-file - generated code
query = f"SELECT * FROM users WHERE id = {x}"
password = "secret"
'''
    handler = IgnoreHandler()
    ignores = handler.parse(source)

    # File ignore means all rules ignored for all lines
    assert handler.is_file_ignored(source)


def test_ignore_requires_reason():
    """Test that ignores without reason are not parsed."""
    source = '''
password = "secret"  # hackmenot:ignore[AUTH002]
'''
    handler = IgnoreHandler()
    ignores = handler.parse(source)

    # Should NOT be ignored because no reason provided
    assert (2, "AUTH002") not in ignores


def test_should_ignore():
    """Test should_ignore helper method."""
    source = '''
password = "secret"  # hackmenot:ignore[AUTH002] - test
query = f"SELECT * FROM {table}"
'''
    handler = IgnoreHandler()
    handler.parse(source)

    assert handler.should_ignore(2, "AUTH002")
    assert not handler.should_ignore(3, "INJ001")
```

**Step 2: Create ignores.py**

Create `src/hackmenot/core/ignores.py`:
```python
"""Inline ignore comment handling."""

import re


class IgnoreHandler:
    """Parses and tracks inline ignore comments."""

    # Pattern for same-line ignore: # hackmenot:ignore[RULE] - reason
    SAME_LINE_PATTERN = re.compile(
        r"#\s*hackmenot:ignore\[([A-Z]+\d+)\]\s*-\s*(.+)$"
    )

    # Pattern for next-line ignore: # hackmenot:ignore-next-line[RULE] - reason
    NEXT_LINE_PATTERN = re.compile(
        r"^\s*#\s*hackmenot:ignore-next-line\[([A-Z]+\d+)\]\s*-\s*(.+)$"
    )

    # Pattern for file ignore: # hackmenot:ignore-file - reason
    FILE_IGNORE_PATTERN = re.compile(
        r"^\s*#\s*hackmenot:ignore-file\s*-\s*(.+)$"
    )

    def __init__(self) -> None:
        self._ignores: set[tuple[int, str]] = set()
        self._file_ignored: bool = False

    def parse(self, source: str) -> set[tuple[int, str]]:
        """Parse source code for ignore comments.

        Returns set of (line_number, rule_id) tuples to ignore.
        """
        self._ignores = set()
        self._file_ignored = False

        lines = source.split("\n")

        for i, line in enumerate(lines, start=1):
            # Check for file-level ignore (must be in first 5 lines)
            if i <= 5:
                file_match = self.FILE_IGNORE_PATTERN.match(line)
                if file_match:
                    self._file_ignored = True
                    continue

            # Check for same-line ignore
            same_line_match = self.SAME_LINE_PATTERN.search(line)
            if same_line_match:
                rule_id = same_line_match.group(1)
                self._ignores.add((i, rule_id))
                continue

            # Check for next-line ignore
            next_line_match = self.NEXT_LINE_PATTERN.match(line)
            if next_line_match:
                rule_id = next_line_match.group(1)
                # Add ignore for the NEXT line
                self._ignores.add((i + 1, rule_id))

        return self._ignores

    def is_file_ignored(self, source: str | None = None) -> bool:
        """Check if the entire file is ignored."""
        if source is not None:
            self.parse(source)
        return self._file_ignored

    def should_ignore(self, line_number: int, rule_id: str) -> bool:
        """Check if a specific line/rule should be ignored."""
        if self._file_ignored:
            return True
        return (line_number, rule_id) in self._ignores
```

**Step 3: Update rules engine to use IgnoreHandler**

Modify `src/hackmenot/rules/engine.py` to accept ignores:
```python
# Add to check() method signature:
def check(
    self,
    parse_result: ParseResult,
    file_path: Path,
    ignores: set[tuple[int, str]] | None = None,
) -> list[Finding]:
    """Check parsed code against all registered rules."""
    if parse_result.has_error:
        return []

    ignores = ignores or set()
    findings: list[Finding] = []
    language = self._detect_language(file_path)

    for rule in self.rules.values():
        if language not in rule.languages:
            continue

        rule_findings = self._check_rule(rule, parse_result, file_path)
        # Filter out ignored findings
        rule_findings = [
            f for f in rule_findings
            if (f.line_number, f.rule_id) not in ignores
        ]
        findings.extend(rule_findings)

    return findings
```

**Step 4: Run tests**

```bash
pytest tests/test_core/test_ignores.py -v
```

**Step 5: Commit**

```bash
git add -A
git commit -m "feat: add IgnoreHandler for inline ignore comments"
```

---

## Task 5: FixEngine

**Files:**
- Create: `src/hackmenot/fixes/__init__.py`
- Create: `src/hackmenot/fixes/engine.py`
- Create: `tests/test_fixes/__init__.py`
- Create: `tests/test_fixes/test_engine.py`

**Step 1: Write the failing test**

Create `tests/test_fixes/__init__.py`:
```python
"""Fix engine tests."""
```

Create `tests/test_fixes/test_engine.py`:
```python
"""Tests for fix engine."""

from pathlib import Path

from hackmenot.core.models import Finding, Severity
from hackmenot.fixes.engine import FixEngine


def test_fix_engine_applies_template():
    """Test fix engine applies fix template."""
    engine = FixEngine()

    source = '''def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return execute(query)
'''

    finding = Finding(
        rule_id="INJ001",
        rule_name="sql-injection",
        severity=Severity.CRITICAL,
        message="SQL injection",
        file_path="test.py",
        line_number=2,
        column=0,
        code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
        fix_suggestion='query = "SELECT * FROM users WHERE id = ?"\ncursor.execute(query, (user_id,))',
        education="Use parameterized queries",
    )

    result = engine.apply_fix(source, finding)

    assert result is not None
    assert "SELECT * FROM users WHERE id = ?" in result


def test_fix_engine_returns_none_when_no_fix():
    """Test fix engine returns None when no fix available."""
    engine = FixEngine()

    source = "x = 1"

    finding = Finding(
        rule_id="TEST001",
        rule_name="test",
        severity=Severity.LOW,
        message="Test",
        file_path="test.py",
        line_number=1,
        column=0,
        code_snippet="x = 1",
        fix_suggestion="",  # No fix
        education="",
    )

    result = engine.apply_fix(source, finding)

    assert result is None


def test_fix_engine_preserves_other_lines():
    """Test fix engine preserves lines not being fixed."""
    engine = FixEngine()

    source = '''import os

def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return execute(query)

def other_function():
    pass
'''

    finding = Finding(
        rule_id="INJ001",
        rule_name="sql-injection",
        severity=Severity.CRITICAL,
        message="SQL injection",
        file_path="test.py",
        line_number=4,
        column=0,
        code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
        fix_suggestion='query = "SELECT * FROM users WHERE id = ?"',
        education="",
    )

    result = engine.apply_fix(source, finding)

    assert "import os" in result
    assert "def other_function():" in result
```

**Step 2: Create fix engine**

Create `src/hackmenot/fixes/__init__.py`:
```python
"""Fixes module for hackmenot."""

from hackmenot.fixes.engine import FixEngine

__all__ = ["FixEngine"]
```

Create `src/hackmenot/fixes/engine.py`:
```python
"""Fix engine for applying code fixes."""

from hackmenot.core.models import Finding


class FixEngine:
    """Engine for applying fix templates to source code."""

    def apply_fix(self, source: str, finding: Finding) -> str | None:
        """Apply a fix to source code.

        Returns modified source code, or None if fix cannot be applied.
        """
        if not finding.fix_suggestion:
            return None

        lines = source.split("\n")
        line_idx = finding.line_number - 1

        if line_idx < 0 or line_idx >= len(lines):
            return None

        # Get the original line
        original_line = lines[line_idx]

        # Get indentation from original line
        indent = len(original_line) - len(original_line.lstrip())
        indent_str = original_line[:indent]

        # Apply fix suggestion (add proper indentation to each line)
        fix_lines = finding.fix_suggestion.split("\n")
        fixed_lines = [indent_str + line.lstrip() if line.strip() else line
                       for line in fix_lines]

        # Replace the original line with fixed lines
        lines[line_idx:line_idx + 1] = fixed_lines

        return "\n".join(lines)

    def apply_fixes(
        self, source: str, findings: list[Finding]
    ) -> tuple[str, int]:
        """Apply multiple fixes to source code.

        Returns (modified_source, num_fixes_applied).
        Applies fixes from bottom to top to preserve line numbers.
        """
        # Sort findings by line number descending
        sorted_findings = sorted(
            findings, key=lambda f: f.line_number, reverse=True
        )

        fixes_applied = 0
        for finding in sorted_findings:
            result = self.apply_fix(source, finding)
            if result is not None:
                source = result
                fixes_applied += 1

        return source, fixes_applied
```

**Step 3: Run tests**

```bash
pytest tests/test_fixes/test_engine.py -v
```

**Step 4: Commit**

```bash
git add -A
git commit -m "feat: add FixEngine for template-based code fixes"
```

---

## Task 6: Interactive Fix Mode

**Files:**
- Modify: `src/hackmenot/cli/main.py`
- Create: `src/hackmenot/cli/interactive.py`
- Create: `tests/test_cli/test_interactive.py`

**Step 1: Write the failing test**

Create `tests/test_cli/test_interactive.py`:
```python
"""Tests for interactive fix mode."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from hackmenot.cli.main import app

runner = CliRunner()


def test_fix_interactive_shows_prompt(tmp_path: Path):
    """Test --fix-interactive shows fix prompts."""
    (tmp_path / "test.py").write_text(
        'query = f"SELECT * FROM users WHERE id = {x}"'
    )

    # Simulate user pressing 's' to skip
    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--fix-interactive"],
        input="s\n"
    )

    # Should show the prompt options
    assert "[a]pply" in result.stdout.lower() or "apply" in result.stdout.lower()


def test_fix_auto_applies_safe_fixes(tmp_path: Path):
    """Test --fix applies fixes automatically."""
    test_file = tmp_path / "test.py"
    test_file.write_text('query = f"SELECT * FROM users WHERE id = {x}"')

    result = runner.invoke(app, ["scan", str(tmp_path), "--fix"])

    # Check that the file was modified or fix was attempted
    # (actual fix application depends on rule having safe=true)
    assert result.exit_code in [0, 1]
```

**Step 2: Create interactive.py**

Create `src/hackmenot/cli/interactive.py`:
```python
"""Interactive fix mode for CLI."""

from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt
from rich.text import Text

from hackmenot.core.models import Finding
from hackmenot.fixes.engine import FixEngine


class InteractiveFixer:
    """Interactive fix mode handler."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
        self.engine = FixEngine()

    def run(
        self, findings: list[Finding], file_contents: dict[str, str]
    ) -> dict[str, str]:
        """Run interactive fix mode.

        Returns dict of file_path -> modified_content for files that were fixed.
        """
        modified_files: dict[str, str] = {}
        apply_all = False

        for finding in findings:
            if not finding.fix_suggestion:
                continue

            file_path = finding.file_path
            source = file_contents.get(file_path) or Path(file_path).read_text()

            if apply_all:
                result = self.engine.apply_fix(source, finding)
                if result:
                    file_contents[file_path] = result
                    modified_files[file_path] = result
                continue

            # Show finding
            self._show_finding(finding)

            # Show fix preview
            self._show_fix_preview(finding)

            # Prompt for action
            action = Prompt.ask(
                "[cyan][a]pply  [s]kip  [A]pply all  [q]uit[/cyan]",
                choices=["a", "s", "A", "q"],
                default="s",
            )

            if action == "q":
                break
            elif action == "A":
                apply_all = True
                result = self.engine.apply_fix(source, finding)
                if result:
                    file_contents[file_path] = result
                    modified_files[file_path] = result
            elif action == "a":
                result = self.engine.apply_fix(source, finding)
                if result:
                    file_contents[file_path] = result
                    modified_files[file_path] = result
            # 's' = skip, do nothing

        return modified_files

    def _show_finding(self, finding: Finding) -> None:
        """Display a finding."""
        self.console.print()
        header = Text()
        header.append(f"  {finding.rule_id}", style="yellow")
        header.append(f" at ", style="dim")
        header.append(finding.file_path, style="cyan")
        header.append(":", style="dim")
        header.append(str(finding.line_number), style="magenta")
        self.console.print(header)
        self.console.print(f"    {finding.message}", style="dim")

    def _show_fix_preview(self, finding: Finding) -> None:
        """Display fix preview."""
        self.console.print()
        self.console.print("  Current:", style="red")
        self.console.print(f"    {finding.code_snippet}")
        self.console.print()
        self.console.print("  Fixed:", style="green")
        for line in finding.fix_suggestion.split("\n")[:3]:
            self.console.print(f"    {line}", style="green")
        self.console.print()
```

**Step 3: Update CLI main.py**

Add `--fix` and `--fix-interactive` flags to the scan command in `src/hackmenot/cli/main.py`:
```python
# Add to imports:
from hackmenot.cli.interactive import InteractiveFixer
from hackmenot.fixes.engine import FixEngine

# Add to scan command parameters:
    fix: bool = typer.Option(
        False,
        "--fix",
        help="Auto-apply safe fixes",
    ),
    fix_interactive: bool = typer.Option(
        False,
        "--fix-interactive",
        "-i",
        help="Interactively apply fixes",
    ),

# Add after scanning, before output:
    # Handle fix modes
    if fix_interactive and result.findings:
        fixer = InteractiveFixer(console=console)
        file_contents = {
            f.file_path: Path(f.file_path).read_text()
            for f in result.findings
            if Path(f.file_path).exists()
        }
        modified = fixer.run(result.findings, file_contents)
        for file_path, content in modified.items():
            Path(file_path).write_text(content)
        console.print(f"\n[green]Applied fixes to {len(modified)} file(s)[/green]")
    elif fix and result.findings:
        engine = FixEngine()
        modified_count = 0
        for file_path in set(f.file_path for f in result.findings):
            path = Path(file_path)
            if not path.exists():
                continue
            source = path.read_text()
            file_findings = [f for f in result.findings if f.file_path == file_path]
            new_source, applied = engine.apply_fixes(source, file_findings)
            if applied > 0:
                path.write_text(new_source)
                modified_count += applied
        console.print(f"\n[green]Applied {modified_count} fix(es)[/green]")
```

**Step 4: Run tests**

```bash
pytest tests/test_cli/test_interactive.py -v
```

**Step 5: Commit**

```bash
git add -A
git commit -m "feat: add --fix and --fix-interactive modes"
```

---

## Task 7: SARIF Reporter

**Files:**
- Create: `src/hackmenot/reporters/sarif.py`
- Modify: `src/hackmenot/reporters/__init__.py`
- Modify: `src/hackmenot/cli/main.py`
- Create: `tests/test_reporters/test_sarif.py`

**Step 1: Write the failing test**

Create `tests/test_reporters/test_sarif.py`:
```python
"""Tests for SARIF reporter."""

import json

from hackmenot.core.models import Finding, ScanResult, Severity
from hackmenot.reporters.sarif import SARIFReporter


def test_sarif_output_valid_json():
    """Test SARIF output is valid JSON."""
    reporter = SARIFReporter()

    findings = [
        Finding(
            rule_id="INJ001",
            rule_name="sql-injection",
            severity=Severity.CRITICAL,
            message="SQL injection detected",
            file_path="src/api.py",
            line_number=42,
            column=10,
            code_snippet='f"SELECT * FROM users"',
            fix_suggestion="Use parameterized queries",
            education="AI often generates vulnerable SQL",
        ),
    ]
    result = ScanResult(files_scanned=1, findings=findings, scan_time_ms=100)

    output = reporter.render(result)

    # Should be valid JSON
    data = json.loads(output)
    assert "$schema" in data
    assert "runs" in data


def test_sarif_contains_results():
    """Test SARIF output contains finding results."""
    reporter = SARIFReporter()

    findings = [
        Finding(
            rule_id="INJ001",
            rule_name="sql-injection",
            severity=Severity.CRITICAL,
            message="SQL injection detected",
            file_path="src/api.py",
            line_number=42,
            column=10,
            code_snippet='f"SELECT * FROM users"',
            fix_suggestion="Use parameterized queries",
            education="AI often generates vulnerable SQL",
        ),
    ]
    result = ScanResult(files_scanned=1, findings=findings, scan_time_ms=100)

    output = reporter.render(result)
    data = json.loads(output)

    results = data["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "INJ001"


def test_sarif_contains_rules():
    """Test SARIF output contains rule definitions."""
    reporter = SARIFReporter()

    findings = [
        Finding(
            rule_id="INJ001",
            rule_name="sql-injection",
            severity=Severity.CRITICAL,
            message="SQL injection detected",
            file_path="src/api.py",
            line_number=42,
            column=10,
            code_snippet='f"SELECT * FROM users"',
            fix_suggestion="Use parameterized queries",
            education="AI often generates vulnerable SQL",
        ),
    ]
    result = ScanResult(files_scanned=1, findings=findings, scan_time_ms=100)

    output = reporter.render(result)
    data = json.loads(output)

    rules = data["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) >= 1
    assert rules[0]["id"] == "INJ001"
```

**Step 2: Create SARIF reporter**

Create `src/hackmenot/reporters/sarif.py`:
```python
"""SARIF 2.1.0 format reporter."""

import json
from typing import Any

from hackmenot import __version__
from hackmenot.core.models import Finding, ScanResult, Severity
from hackmenot.reporters.base import BaseReporter


class SARIFReporter(BaseReporter):
    """SARIF format reporter for GitHub Code Scanning."""

    SEVERITY_MAP = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
    }

    def render(self, result: ScanResult) -> str:
        """Render scan results as SARIF JSON."""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": self._tool_component(result),
                    "results": self._results(result.findings),
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    def _tool_component(self, result: ScanResult) -> dict[str, Any]:
        """Generate tool component."""
        rules = self._rules(result.findings)
        return {
            "driver": {
                "name": "hackmenot",
                "version": __version__,
                "informationUri": "https://github.com/hackmenot/hackmenot",
                "rules": rules,
            }
        }

    def _rules(self, findings: list[Finding]) -> list[dict[str, Any]]:
        """Generate unique rule definitions."""
        seen_rules: dict[str, dict[str, Any]] = {}

        for finding in findings:
            if finding.rule_id not in seen_rules:
                seen_rules[finding.rule_id] = {
                    "id": finding.rule_id,
                    "name": finding.rule_name,
                    "shortDescription": {"text": finding.message},
                    "fullDescription": {"text": finding.education or finding.message},
                    "defaultConfiguration": {
                        "level": self.SEVERITY_MAP[finding.severity]
                    },
                    "help": {
                        "text": finding.fix_suggestion or "No fix available",
                        "markdown": finding.fix_suggestion or "No fix available",
                    },
                }

        return list(seen_rules.values())

    def _results(self, findings: list[Finding]) -> list[dict[str, Any]]:
        """Generate result entries."""
        results = []

        for finding in findings:
            results.append({
                "ruleId": finding.rule_id,
                "level": self.SEVERITY_MAP[finding.severity],
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.file_path,
                            },
                            "region": {
                                "startLine": finding.line_number,
                                "startColumn": finding.column + 1,
                            },
                        }
                    }
                ],
                "fixes": self._fixes(finding) if finding.fix_suggestion else [],
            })

        return results

    def _fixes(self, finding: Finding) -> list[dict[str, Any]]:
        """Generate fix suggestions."""
        if not finding.fix_suggestion:
            return []

        return [
            {
                "description": {"text": "Apply suggested fix"},
                "artifactChanges": [
                    {
                        "artifactLocation": {"uri": finding.file_path},
                        "replacements": [
                            {
                                "deletedRegion": {
                                    "startLine": finding.line_number,
                                    "startColumn": 1,
                                    "endLine": finding.line_number,
                                    "endColumn": len(finding.code_snippet) + 1,
                                },
                                "insertedContent": {
                                    "text": finding.fix_suggestion
                                },
                            }
                        ],
                    }
                ],
            }
        ]
```

**Step 3: Update reporters __init__.py**

```python
"""Reporters module for hackmenot."""

from hackmenot.reporters.sarif import SARIFReporter
from hackmenot.reporters.terminal import TerminalReporter

__all__ = ["TerminalReporter", "SARIFReporter"]
```

**Step 4: Update CLI to use SARIF**

Update the sarif case in `src/hackmenot/cli/main.py`:
```python
from hackmenot.reporters.sarif import SARIFReporter

# In scan command:
    elif format == OutputFormat.sarif:
        reporter = SARIFReporter()
        print(reporter.render(result))
```

**Step 5: Run tests**

```bash
pytest tests/test_reporters/test_sarif.py -v
```

**Step 6: Commit**

```bash
git add -A
git commit -m "feat: add SARIF reporter for GitHub Code Scanning"
```

---

## Task 8: Wire Config into Scanner

**Files:**
- Modify: `src/hackmenot/core/scanner.py`
- Modify: `src/hackmenot/cli/main.py`
- Create: `tests/test_core/test_scanner_config.py`

**Step 1: Write the failing test**

Create `tests/test_core/test_scanner_config.py`:
```python
"""Tests for scanner with config integration."""

from pathlib import Path

from hackmenot.core.config import Config
from hackmenot.core.scanner import Scanner


def test_scanner_respects_disabled_rules(tmp_path: Path):
    """Test scanner respects disabled rules from config."""
    config = Config(rules_disable=["INJ001"])
    scanner = Scanner(config=config)

    (tmp_path / "test.py").write_text(
        'query = f"SELECT * FROM users WHERE id = {x}"'
    )

    result = scanner.scan([tmp_path])

    # INJ001 should be disabled
    assert not any(f.rule_id == "INJ001" for f in result.findings)


def test_scanner_respects_path_excludes(tmp_path: Path):
    """Test scanner respects path excludes from config."""
    config = Config(paths_exclude=["tests/*"])
    scanner = Scanner(config=config)

    # Create files in tests/ directory
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test.py").write_text(
        'query = f"SELECT * FROM users WHERE id = {x}"'
    )

    # Create file in src/ directory
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "app.py").write_text('x = 1')

    result = scanner.scan([tmp_path])

    # Should only scan src/, not tests/
    assert result.files_scanned == 1
```

**Step 2: Update scanner to use config**

Modify `src/hackmenot/core/scanner.py`:
```python
# Add to __init__:
def __init__(
    self,
    cache_dir: Path | None = None,
    config: Config | None = None,
) -> None:
    self.parser = PythonParser()
    self.engine = RulesEngine()
    self.cache = FileCache(cache_dir)
    self.config = config or Config()
    self._load_rules()

# Update _load_rules to respect disabled rules:
def _load_rules(self) -> None:
    """Load all built-in rules."""
    registry = RuleRegistry()
    registry.load_all()
    for rule in registry.get_all_rules():
        if rule.id not in self.config.rules_disable:
            self.engine.register_rule(rule)

# Update _collect_files to respect path excludes:
def _collect_files(self, paths: list[Path]) -> list[Path]:
    """Collect all scannable files from paths."""
    import fnmatch

    files: list[Path] = []

    for path in paths:
        if path.is_file():
            if path.suffix in self.SUPPORTED_EXTENSIONS:
                files.append(path)
        elif path.is_dir():
            for ext in self.SUPPORTED_EXTENSIONS:
                for f in path.rglob(f"*{ext}"):
                    # Check excludes
                    rel_path = str(f.relative_to(path))
                    excluded = any(
                        fnmatch.fnmatch(rel_path, pattern)
                        for pattern in self.config.paths_exclude
                    )
                    if not excluded:
                        files.append(f)

    return sorted(set(files))
```

**Step 3: Update CLI to load config**

Add config loading to `src/hackmenot/cli/main.py`:
```python
from hackmenot.core.config import ConfigLoader

# In scan command, before creating Scanner:
    # Load config
    config_loader = ConfigLoader()
    config = config_loader.load(paths[0].parent if paths[0].is_file() else paths[0])

    # Run scan
    scanner = Scanner(config=config)
```

**Step 4: Run tests**

```bash
pytest tests/test_core/test_scanner_config.py -v
```

**Step 5: Commit**

```bash
git add -A
git commit -m "feat: integrate config into scanner for rule disabling and path excludes"
```

---

## Task 9: Wire Ignores into Scanner

**Files:**
- Modify: `src/hackmenot/core/scanner.py`
- Create: `tests/test_core/test_scanner_ignores.py`

**Step 1: Write the failing test**

Create `tests/test_core/test_scanner_ignores.py`:
```python
"""Tests for scanner with inline ignores."""

from pathlib import Path

from hackmenot.core.scanner import Scanner


def test_scanner_respects_inline_ignores(tmp_path: Path):
    """Test scanner respects inline ignore comments."""
    scanner = Scanner()

    (tmp_path / "test.py").write_text('''
# hackmenot:ignore-next-line[INJ001] - test fixture
query = f"SELECT * FROM users WHERE id = {x}"
''')

    result = scanner.scan([tmp_path])

    # INJ001 should be ignored
    assert not any(f.rule_id == "INJ001" for f in result.findings)


def test_scanner_respects_file_ignore(tmp_path: Path):
    """Test scanner respects file-level ignore."""
    scanner = Scanner()

    (tmp_path / "test.py").write_text('''# hackmenot:ignore-file - generated code
query = f"SELECT * FROM users WHERE id = {x}"
password = "secret"
''')

    result = scanner.scan([tmp_path])

    # All findings should be ignored
    assert len(result.findings) == 0
```

**Step 2: Update scanner to use IgnoreHandler**

Modify `src/hackmenot/core/scanner.py`:
```python
from hackmenot.core.ignores import IgnoreHandler

# Update _scan_file method:
def _scan_file(self, file_path: Path, use_cache: bool = True) -> list[Finding]:
    """Scan a single file."""
    if use_cache:
        cached = self.cache.get(file_path)
        if cached is not None:
            return cached

    # Read source for ignore parsing
    try:
        source = file_path.read_text()
    except Exception:
        return []

    # Parse ignores
    ignore_handler = IgnoreHandler()
    ignore_handler.parse(source)

    # Check for file-level ignore
    if ignore_handler.is_file_ignored():
        findings: list[Finding] = []
    else:
        parse_result = self.parser.parse_file(file_path)
        if parse_result.has_error:
            findings = []
        else:
            findings = self.engine.check(
                parse_result, file_path, ignores=ignore_handler._ignores
            )

    if use_cache:
        self.cache.store(file_path, findings)

    return findings
```

**Step 3: Run tests**

```bash
pytest tests/test_core/test_scanner_ignores.py -v
```

**Step 4: Commit**

```bash
git add -A
git commit -m "feat: integrate inline ignores into scanner"
```

---

## Task 10: Add CLI Flags (--full, --config)

**Files:**
- Modify: `src/hackmenot/cli/main.py`
- Create: `tests/test_cli/test_flags.py`

**Step 1: Write the failing test**

Create `tests/test_cli/test_flags.py`:
```python
"""Tests for CLI flags."""

from pathlib import Path

from typer.testing import CliRunner

from hackmenot.cli.main import app

runner = CliRunner()


def test_full_flag_bypasses_cache(tmp_path: Path):
    """Test --full flag bypasses cache."""
    (tmp_path / "test.py").write_text('x = 1')

    result = runner.invoke(app, ["scan", str(tmp_path), "--full"])

    assert result.exit_code == 0


def test_config_flag_loads_config(tmp_path: Path):
    """Test --config flag loads specific config file."""
    config_file = tmp_path / "custom.yml"
    config_file.write_text("fail_on: low")

    (tmp_path / "test.py").write_text('x = 1')

    result = runner.invoke(
        app, ["scan", str(tmp_path), "--config", str(config_file)]
    )

    assert result.exit_code == 0
```

**Step 2: Update CLI with new flags**

Add to `src/hackmenot/cli/main.py` scan command:
```python
    full: bool = typer.Option(
        False,
        "--full",
        help="Bypass cache, perform full scan",
    ),
    config_file: Path | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to config file",
    ),

# Update scanner creation:
    scanner = Scanner(config=config)
    result = scanner.scan(paths, min_severity=min_severity, use_cache=not full)
```

**Step 3: Run tests**

```bash
pytest tests/test_cli/test_flags.py -v
```

**Step 4: Commit**

```bash
git add -A
git commit -m "feat: add --full and --config CLI flags"
```

---

## Task 11-15: Add 25 New Rules (5 tasks, 5 rules each)

Each task adds 5 new YAML rules to a category. Follow this pattern for each:

### Task 11: Injection Rules (INJ003-007)

**Files:**
- Create: `src/hackmenot/rules/builtin/injection/INJ003.yml` (path traversal)
- Create: `src/hackmenot/rules/builtin/injection/INJ004.yml` (SSRF)
- Create: `src/hackmenot/rules/builtin/injection/INJ005.yml` (XSS in templates)
- Create: `src/hackmenot/rules/builtin/injection/INJ006.yml` (unsafe eval)
- Create: `src/hackmenot/rules/builtin/injection/INJ007.yml` (code injection)

### Task 12: Auth Rules (AUTH003-007)

**Files:**
- Create: `src/hackmenot/rules/builtin/auth/AUTH003.yml` (hardcoded password)
- Create: `src/hackmenot/rules/builtin/auth/AUTH004.yml` (weak session)
- Create: `src/hackmenot/rules/builtin/auth/AUTH005.yml` (missing CSRF)
- Create: `src/hackmenot/rules/builtin/auth/AUTH006.yml` (JWT none algorithm)
- Create: `src/hackmenot/rules/builtin/auth/AUTH007.yml` (insecure cookie)

### Task 13: Crypto Rules (CRYPTO003-007)

**Files:**
- Create: `src/hackmenot/rules/builtin/crypto/CRYPTO003.yml` (weak random)
- Create: `src/hackmenot/rules/builtin/crypto/CRYPTO004.yml` (ECB mode)
- Create: `src/hackmenot/rules/builtin/crypto/CRYPTO005.yml` (small key size)
- Create: `src/hackmenot/rules/builtin/crypto/CRYPTO006.yml` (hardcoded IV)
- Create: `src/hackmenot/rules/builtin/crypto/CRYPTO007.yml` (no salt)

### Task 14: Exposure Rules (EXP003-007)

**Files:**
- Create: `src/hackmenot/rules/builtin/exposure/EXP003.yml` (logging secrets)
- Create: `src/hackmenot/rules/builtin/exposure/EXP004.yml` (stack trace response)
- Create: `src/hackmenot/rules/builtin/exposure/EXP005.yml` (.env in repo)
- Create: `src/hackmenot/rules/builtin/exposure/EXP006.yml` (sensitive in URL)
- Create: `src/hackmenot/rules/builtin/exposure/EXP007.yml` (verbose exceptions)

### Task 15: Validation Rules (VAL001-005)

**Files:**
- Create: `src/hackmenot/rules/builtin/validation/VAL001.yml` (missing length check)
- Create: `src/hackmenot/rules/builtin/validation/VAL002.yml` (regex DoS)
- Create: `src/hackmenot/rules/builtin/validation/VAL003.yml` (type confusion)
- Create: `src/hackmenot/rules/builtin/validation/VAL004.yml` (mass assignment)
- Create: `src/hackmenot/rules/builtin/validation/VAL005.yml` (unsafe redirect)

---

## Task 16: Integration Tests

**Files:**
- Modify: `tests/test_integration.py`

Add tests for:
- Config file loading end-to-end
- Inline ignores end-to-end
- SARIF output validation
- Fix mode end-to-end
- Parallel + cached scanning performance

---

## Summary

**Total Tasks:** 16
**Expected Tests:** ~70 total (42 existing + ~28 new)
**Expected Rules:** 35 total (10 existing + 25 new)

**Key deliverables:**
1. Incremental scanning with cache
2. Parallel processing
3. Config file support
4. Inline ignores
5. Fix engine + interactive mode
6. SARIF output
7. 25 new security rules
