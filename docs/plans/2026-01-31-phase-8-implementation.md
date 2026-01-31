# Phase 8: Performance + GitHub Action Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 3-5x faster scanning for large repos + one-liner GitHub Action for CI/CD.

**Architecture:** Performance gains from smart directory filtering, git-aware scanning, and regex caching. GitHub Action uses composite action with Python entrypoint.

**Tech Stack:** Python 3.11+, ThreadPoolExecutor, GitHub Actions composite, SARIF

---

## Part 1: Performance Optimization

### Task 1: Add SKIP_DIRS early filtering

**Files:**
- Modify: `src/hackmenot/core/scanner.py`
- Test: `tests/test_core/test_scanner.py`

**Step 1: Write the failing test**

```python
# tests/test_core/test_scanner.py

def test_skip_dirs_excludes_node_modules(tmp_path: Path):
    """Test that node_modules is skipped during file collection."""
    # Create files in node_modules (should be skipped)
    nm_dir = tmp_path / "node_modules" / "package"
    nm_dir.mkdir(parents=True)
    (nm_dir / "index.js").write_text("eval('bad')")

    # Create file outside node_modules (should be scanned)
    (tmp_path / "app.py").write_text("x = 1")

    scanner = Scanner()
    result = scanner.scan([tmp_path])

    # Only app.py should be scanned, not the file in node_modules
    assert result.files_scanned == 1


def test_skip_dirs_excludes_pycache(tmp_path: Path):
    """Test that __pycache__ is skipped."""
    cache_dir = tmp_path / "__pycache__"
    cache_dir.mkdir()
    (cache_dir / "module.cpython-311.pyc").write_text("x = 1")
    (tmp_path / "app.py").write_text("x = 1")

    scanner = Scanner()
    result = scanner.scan([tmp_path])

    assert result.files_scanned == 1
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_core/test_scanner.py::test_skip_dirs_excludes_node_modules -v`
Expected: FAIL (node_modules files are currently scanned)

**Step 3: Implement SKIP_DIRS in scanner**

```python
# src/hackmenot/core/scanner.py - add after class constants

SKIP_DIRS = {
    'node_modules', '.git', '__pycache__', '.venv', 'venv',
    'vendor', 'dist', 'build', '.next', '.nuxt', 'coverage',
    '.tox', '.eggs', '.mypy_cache', '.pytest_cache', '.ruff_cache',
    'site-packages', '.gradle', 'target', 'bin', 'obj',
}
```

Update `_collect_files` method:

```python
def _collect_files(self, paths: list[Path]) -> list[Path]:
    """Collect all scannable files from paths, respecting path excludes."""
    files: list[Path] = []

    for path in paths:
        if path.is_file():
            if path.suffix in self.SUPPORTED_EXTENSIONS:
                files.append(path)
        elif path.is_dir():
            for root, dirs, filenames in os.walk(path):
                # Skip directories early (modifies dirs in-place)
                dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]

                for filename in filenames:
                    file_path = Path(root) / filename
                    if file_path.suffix in self.SUPPORTED_EXTENSIONS:
                        files.append(file_path)

    # Filter out excluded paths from config
    if self.config.paths_exclude:
        files = [f for f in files if not self._is_excluded(f, paths)]

    return sorted(set(files))
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_core/test_scanner.py -v -k skip_dirs`
Expected: PASS

**Step 5: Commit**

```bash
git add src/hackmenot/core/scanner.py tests/test_core/test_scanner.py
git commit -m "perf: add SKIP_DIRS early filtering for node_modules, __pycache__, etc."
```

---

### Task 2: Add --changed-since flag for git-aware scanning

**Files:**
- Modify: `src/hackmenot/cli/git.py`
- Modify: `src/hackmenot/cli/main.py`
- Test: `tests/test_cli/test_changed_since.py`

**Step 1: Write the failing test**

```python
# tests/test_cli/test_changed_since.py
"""Tests for --changed-since flag."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from hackmenot.cli.main import app

runner = CliRunner()


def test_changed_since_requires_git_repo(tmp_path: Path):
    """Test that --changed-since requires a git repo."""
    (tmp_path / "test.py").write_text("x = 1")

    with patch("hackmenot.cli.main.is_git_repo", return_value=False):
        result = runner.invoke(app, ["scan", str(tmp_path), "--changed-since", "main"])

    assert result.exit_code == 1
    assert "git repository" in result.stdout.lower()


def test_changed_since_flag_accepted(tmp_path: Path):
    """Test that --changed-since flag is accepted."""
    (tmp_path / "test.py").write_text("x = 1")

    with patch("hackmenot.cli.main.is_git_repo", return_value=True):
        with patch("hackmenot.cli.main.get_changed_files", return_value=[]):
            result = runner.invoke(app, ["scan", str(tmp_path), "--changed-since", "main"])

    # Should succeed with no files to scan
    assert result.exit_code == 0
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli/test_changed_since.py -v`
Expected: FAIL (--changed-since not implemented)

**Step 3: Add get_changed_files to git.py**

```python
# src/hackmenot/cli/git.py - add new function

def get_changed_files(ref: str) -> list[Path]:
    """Get list of files changed since a git ref.

    Args:
        ref: Git reference (branch, tag, or commit) to compare against.

    Returns:
        List of Path objects for changed files.
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", f"{ref}...HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        files = [Path(f) for f in result.stdout.strip().split("\n") if f]
        return [f for f in files if f.exists()]
    except subprocess.CalledProcessError:
        # Try without the three-dot syntax for older git versions
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", ref, "HEAD"],
                capture_output=True,
                text=True,
                check=True,
            )
            files = [Path(f) for f in result.stdout.strip().split("\n") if f]
            return [f for f in files if f.exists()]
        except subprocess.CalledProcessError:
            return []
```

**Step 4: Add --changed-since to CLI**

```python
# src/hackmenot/cli/main.py - add import
from hackmenot.cli.git import get_staged_files, get_changed_files, is_git_repo

# Add to scan() function parameters (after staged):
    changed_since: str | None = typer.Option(
        None,
        "--changed-since",
        help="Only scan files changed since git ref (branch/tag/commit)",
    ),

# Add handling after staged handling block:
    # Handle --changed-since flag
    if changed_since:
        if not is_git_repo():
            scan_console.print("Error: --changed-since requires a git repository")
            raise typer.Exit(1)

        changed_files = get_changed_files(changed_since)
        if not changed_files:
            scan_console.print(f"No files changed since {changed_since}")
            raise typer.Exit(0)

        # Filter to supported extensions
        supported_extensions = Scanner.SUPPORTED_EXTENSIONS
        scan_paths = [
            f for f in changed_files
            if f.suffix in supported_extensions and f.exists()
        ]

        if not scan_paths:
            scan_console.print("No supported files in changed files")
            raise typer.Exit(0)
```

**Step 5: Run tests to verify they pass**

Run: `pytest tests/test_cli/test_changed_since.py -v`
Expected: PASS

**Step 6: Commit**

```bash
git add src/hackmenot/cli/git.py src/hackmenot/cli/main.py tests/test_cli/test_changed_since.py
git commit -m "feat(cli): add --changed-since flag for git-aware scanning"
```

---

### Task 3: Add cache versioning with rules hash

**Files:**
- Modify: `src/hackmenot/core/cache.py`
- Test: `tests/test_core/test_cache.py`

**Step 1: Write the failing test**

```python
# tests/test_core/test_cache.py - add new tests

def test_cache_invalidates_on_version_change(tmp_path: Path):
    """Test that cache invalidates when hackmenot version changes."""
    cache = FileCache(cache_dir=tmp_path)

    test_file = tmp_path / "test.py"
    test_file.write_text("x = 1")

    findings = [Finding(
        rule_id="TEST001",
        rule_name="test",
        severity=Severity.LOW,
        message="test",
        file_path=str(test_file),
        line_number=1,
    )]

    # Store with current version
    cache.store(test_file, findings)
    assert cache.get(test_file) is not None

    # Simulate version change
    cache._version = "0.0.0-old"
    cache._cache.clear()
    cache._load_cache()

    # Should return None due to version mismatch
    assert cache.get(test_file) is None


def test_cache_includes_rules_hash(tmp_path: Path):
    """Test that cache key includes rules hash."""
    cache = FileCache(cache_dir=tmp_path)

    test_file = tmp_path / "test.py"
    test_file.write_text("x = 1")

    findings = []
    cache.store(test_file, findings)

    # Verify cache metadata includes rules_hash
    cache_data = cache._cache[str(test_file.absolute())]
    assert "rules_hash" in cache_data or len(cache_data) >= 3
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_core/test_cache.py::test_cache_invalidates_on_version_change -v`
Expected: FAIL

**Step 3: Update FileCache with version and rules hash**

```python
# src/hackmenot/core/cache.py - update imports and class

import hashlib
import json
import threading
from pathlib import Path
from typing import Any

from hackmenot import __version__
from hackmenot.core.models import Finding, Severity


class FileCache:
    """Cache for storing scan results by file hash.

    Thread-safe: uses a lock to protect concurrent access.
    Cache invalidates when hackmenot version or rules change.
    """

    CACHE_VERSION = "2"  # Bump to invalidate all caches

    def __init__(self, cache_dir: Path | None = None, rules_hash: str | None = None) -> None:
        self.cache_dir = cache_dir or self._default_cache_dir()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._version = __version__
        self._rules_hash = rules_hash or ""
        self._cache: dict[str, tuple[str, str, str, list[dict[str, Any]]]] = {}
        # (file_hash, version, rules_hash, findings)
        self._lock = threading.Lock()
        self._load_cache()

    # ... rest of class with updated get/store methods:

    def get(self, file_path: Path) -> list[Finding] | None:
        """Get cached results for a file, or None if not cached/stale."""
        key = str(file_path.absolute())
        current_hash = self._file_hash(file_path)

        with self._lock:
            if key not in self._cache:
                return None

            stored_hash, version, rules_hash, findings_data = self._cache[key]

            # Invalidate if file changed
            if stored_hash != current_hash:
                del self._cache[key]
                return None

            # Invalidate if version changed
            if version != self._version:
                del self._cache[key]
                return None

            # Invalidate if rules changed
            if rules_hash != self._rules_hash:
                del self._cache[key]
                return None

            return _deserialize_findings(findings_data)

    def store(self, file_path: Path, findings: list[Finding]) -> None:
        """Store results for a file."""
        key = str(file_path.absolute())
        file_hash = self._file_hash(file_path)
        serialized = _serialize_findings(findings) if findings else []

        with self._lock:
            self._cache[key] = (file_hash, self._version, self._rules_hash, serialized)
            self._save_cache()
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_core/test_cache.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add src/hackmenot/core/cache.py tests/test_core/test_cache.py
git commit -m "perf: add cache versioning with rules hash"
```

---

### Task 4: Add compiled regex cache

**Files:**
- Create: `src/hackmenot/core/regex_cache.py`
- Modify: `src/hackmenot/rules/engine.py`
- Test: `tests/test_core/test_regex_cache.py`

**Step 1: Write the failing test**

```python
# tests/test_core/test_regex_cache.py
"""Tests for compiled regex cache."""

import re
from hackmenot.core.regex_cache import RegexCache


def test_regex_cache_compiles_once():
    """Test that patterns are only compiled once."""
    cache = RegexCache()

    pattern = r"\beval\s*\("

    # First call compiles
    regex1 = cache.get(pattern)
    assert isinstance(regex1, re.Pattern)

    # Second call returns same object
    regex2 = cache.get(pattern)
    assert regex1 is regex2


def test_regex_cache_different_patterns():
    """Test that different patterns get different compiled objects."""
    cache = RegexCache()

    regex1 = cache.get(r"pattern1")
    regex2 = cache.get(r"pattern2")

    assert regex1 is not regex2


def test_regex_cache_stats():
    """Test cache hit/miss statistics."""
    cache = RegexCache()

    cache.get(r"test")
    cache.get(r"test")
    cache.get(r"other")

    assert cache.hits == 1
    assert cache.misses == 2
```

**Step 2: Run test to verify it fails**

Run: `pytest tests/test_core/test_regex_cache.py -v`
Expected: FAIL (module doesn't exist)

**Step 3: Create regex cache module**

```python
# src/hackmenot/core/regex_cache.py
"""Compiled regex pattern cache for performance."""

import re
import threading


class RegexCache:
    """Thread-safe cache for compiled regex patterns.

    Compiles patterns once and reuses them across all file scans.
    """

    def __init__(self) -> None:
        self._cache: dict[str, re.Pattern[str]] = {}
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, pattern: str, flags: int = 0) -> re.Pattern[str]:
        """Get compiled regex pattern, compiling if needed.

        Args:
            pattern: Regex pattern string.
            flags: Optional regex flags.

        Returns:
            Compiled regex pattern.
        """
        key = (pattern, flags)

        with self._lock:
            if key in self._cache:
                self.hits += 1
                return self._cache[key]

            self.misses += 1
            compiled = re.compile(pattern, flags)
            self._cache[key] = compiled
            return compiled

    def clear(self) -> None:
        """Clear the cache."""
        with self._lock:
            self._cache.clear()
            self.hits = 0
            self.misses = 0

    @property
    def size(self) -> int:
        """Number of cached patterns."""
        return len(self._cache)


# Global instance for use across the application
_global_cache = RegexCache()


def get_regex(pattern: str, flags: int = 0) -> re.Pattern[str]:
    """Get compiled regex from global cache."""
    return _global_cache.get(pattern, flags)
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_core/test_regex_cache.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add src/hackmenot/core/regex_cache.py tests/test_core/test_regex_cache.py
git commit -m "perf: add compiled regex cache"
```

---

## Part 2: GitHub Action

### Task 5: Create action.yml

**Files:**
- Create: `action.yml`

**Step 1: Create the action definition**

```yaml
# action.yml
name: 'hackmenot'
description: 'AI-Era Code Security Scanner - Find vulnerabilities that AI coding assistants introduce'
author: 'b0rd3aux'

branding:
  icon: 'shield'
  color: 'purple'

inputs:
  paths:
    description: 'Paths to scan (space-separated)'
    required: false
    default: '.'
  severity:
    description: 'Minimum severity to report (critical, high, medium, low)'
    required: false
    default: 'low'
  fail-on:
    description: 'Minimum severity to fail the check (critical, high, medium, low)'
    required: false
    default: 'high'
  format:
    description: 'Output format (terminal, json, sarif)'
    required: false
    default: 'terminal'
  include-deps:
    description: 'Also scan dependency files'
    required: false
    default: 'false'
  changed-only:
    description: 'Only scan files changed in PR'
    required: false
    default: 'true'

outputs:
  findings:
    description: 'Total number of findings'
    value: ${{ steps.scan.outputs.findings }}
  critical:
    description: 'Number of critical findings'
    value: ${{ steps.scan.outputs.critical }}
  high:
    description: 'Number of high findings'
    value: ${{ steps.scan.outputs.high }}
  sarif-file:
    description: 'Path to SARIF file (if format=sarif)'
    value: ${{ steps.scan.outputs.sarif-file }}

runs:
  using: 'composite'
  steps:
    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.11'

    - name: Cache hackmenot
      uses: actions/cache@v4
      with:
        path: |
          ~/.cache/pip
          ~/.hackmenot
        key: hackmenot-${{ runner.os }}-${{ hashFiles('**/requirements*.txt', '**/pyproject.toml') }}
        restore-keys: |
          hackmenot-${{ runner.os }}-

    - name: Install hackmenot
      shell: bash
      run: pip install hackmenot

    - name: Get changed files
      id: changed
      if: inputs.changed-only == 'true' && github.event_name == 'pull_request'
      shell: bash
      run: |
        echo "files=$(git diff --name-only ${{ github.event.pull_request.base.sha }}...${{ github.sha }} | tr '\n' ' ')" >> $GITHUB_OUTPUT

    - name: Run hackmenot scan
      id: scan
      shell: bash
      env:
        INPUT_PATHS: ${{ inputs.paths }}
        INPUT_SEVERITY: ${{ inputs.severity }}
        INPUT_FAIL_ON: ${{ inputs.fail-on }}
        INPUT_FORMAT: ${{ inputs.format }}
        INPUT_INCLUDE_DEPS: ${{ inputs.include-deps }}
        CHANGED_FILES: ${{ steps.changed.outputs.files }}
      run: |
        # Determine paths to scan
        if [ -n "$CHANGED_FILES" ] && [ "${{ inputs.changed-only }}" == "true" ]; then
          SCAN_PATHS="$CHANGED_FILES"
        else
          SCAN_PATHS="$INPUT_PATHS"
        fi

        # Build command
        CMD="hackmenot scan $SCAN_PATHS --severity $INPUT_SEVERITY --fail-on $INPUT_FAIL_ON --format $INPUT_FORMAT --ci"

        if [ "$INPUT_INCLUDE_DEPS" == "true" ]; then
          CMD="$CMD --include-deps"
        fi

        # Run scan and capture output
        set +e
        OUTPUT=$($CMD 2>&1)
        EXIT_CODE=$?
        set -e

        echo "$OUTPUT"

        # Parse findings count from output
        FINDINGS=$(echo "$OUTPUT" | grep -oP 'Critical: \K\d+' || echo "0")
        CRITICAL=$(echo "$OUTPUT" | grep -oP 'Critical: \K\d+' || echo "0")
        HIGH=$(echo "$OUTPUT" | grep -oP 'High: \K\d+' || echo "0")

        echo "findings=$FINDINGS" >> $GITHUB_OUTPUT
        echo "critical=$CRITICAL" >> $GITHUB_OUTPUT
        echo "high=$HIGH" >> $GITHUB_OUTPUT

        if [ "$INPUT_FORMAT" == "sarif" ]; then
          echo "sarif-file=hackmenot-results.sarif" >> $GITHUB_OUTPUT
        fi

        exit $EXIT_CODE
```

**Step 2: Commit**

```bash
git add action.yml
git commit -m "feat: add GitHub Action for CI/CD integration"
```

---

### Task 6: Add example workflow

**Files:**
- Create: `.github/workflows/example.yml`

**Step 1: Create example workflow**

```yaml
# .github/workflows/example.yml
name: Example - hackmenot Security Scan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Needed for --changed-since

      # Simple usage
      - name: Run hackmenot
        uses: ./
        with:
          fail-on: high

      # Or with SARIF upload
      # - name: Run hackmenot (SARIF)
      #   uses: ./
      #   with:
      #     format: sarif
      #     fail-on: critical
      #
      # - name: Upload SARIF
      #   uses: github/codeql-action/upload-sarif@v3
      #   with:
      #     sarif_file: hackmenot-results.sarif
```

**Step 2: Commit**

```bash
git add .github/workflows/example.yml
git commit -m "docs: add example GitHub Action workflow"
```

---

### Task 7: Update documentation

**Files:**
- Modify: `docs/ci-integration.md`

**Step 1: Update CI documentation**

```markdown
# CI Integration

## GitHub Actions

### Quick Start

Add hackmenot to your workflow with a single line:

```yaml
- uses: b0rd3aux/hackmenot@v1
```

### Full Example

```yaml
name: Security Scan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  hackmenot:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: b0rd3aux/hackmenot@v1
        with:
          severity: medium
          fail-on: high
```

### Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `paths` | Paths to scan | `.` |
| `severity` | Minimum severity to report | `low` |
| `fail-on` | Severity threshold for failure | `high` |
| `format` | Output format (terminal, json, sarif) | `terminal` |
| `include-deps` | Scan dependency files | `false` |
| `changed-only` | Only scan changed files in PR | `true` |

### Outputs

| Output | Description |
|--------|-------------|
| `findings` | Total number of findings |
| `critical` | Number of critical findings |
| `high` | Number of high findings |
| `sarif-file` | Path to SARIF file |

### SARIF Integration

Upload results to GitHub Security tab:

```yaml
- uses: b0rd3aux/hackmenot@v1
  with:
    format: sarif

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: hackmenot-results.sarif
```

### Changed Files Only

By default, hackmenot only scans files changed in the PR for faster CI:

```yaml
- uses: b0rd3aux/hackmenot@v1
  with:
    changed-only: true  # Default
```

To scan all files:

```yaml
- uses: b0rd3aux/hackmenot@v1
  with:
    changed-only: false
```
```

**Step 2: Commit**

```bash
git add docs/ci-integration.md
git commit -m "docs: update CI integration guide with GitHub Action"
```

---

### Task 8: Run all tests and verify

**Step 1: Run full test suite**

```bash
pytest tests/ -v
```

Expected: All tests pass

**Step 2: Test GitHub Action locally (optional)**

```bash
# If you have 'act' installed
act pull_request -j security-scan
```

---

## Summary

| Task | Description | Files |
|------|-------------|-------|
| 1 | SKIP_DIRS filtering | scanner.py |
| 2 | --changed-since flag | git.py, main.py |
| 3 | Cache versioning | cache.py |
| 4 | Regex cache | regex_cache.py |
| 5 | action.yml | action.yml |
| 6 | Example workflow | .github/workflows/ |
| 7 | Documentation | ci-integration.md |
| 8 | Final verification | tests |

**Total: 8 tasks**
