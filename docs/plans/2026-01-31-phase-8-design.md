# Phase 8: Performance Optimization + GitHub Action - Design Document

## Overview

Comprehensive performance optimization for large codebases plus a reusable GitHub Action for CI/CD integration.

**Goals:**
- 3-5x faster scanning on large repos (10k+ files)
- Near-instant repeat scans with warm cache
- One-liner GitHub Action that "just works"

## Performance Optimization

### 1. Large Monorepo Scanning

**Lazy file collection:**
- Use generators instead of building full file lists in memory
- Process files as they're discovered rather than collecting all first

**Parallel directory walking:**
```python
def _collect_files_parallel(self, paths: list[Path]) -> Iterator[Path]:
    """Walk directories in parallel using ThreadPoolExecutor."""
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(self._walk_dir, p): p for p in paths}
        for future in as_completed(futures):
            yield from future.result()
```

**Smart early filtering:**
Skip known non-code directories before checking extensions:
```python
SKIP_DIRS = {
    'node_modules', '.git', '__pycache__', '.venv', 'venv',
    'vendor', 'dist', 'build', '.next', '.nuxt', 'coverage',
    '.tox', '.eggs', '*.egg-info', '.mypy_cache', '.pytest_cache'
}
```

### 2. Repeat Scan Speed

**Cache versioning:**
- Include rule hash in cache key
- Cache auto-invalidates when rules change
- Version bump invalidates old caches

```python
@dataclass
class CacheKey:
    file_hash: str
    rules_hash: str  # Hash of all rule definitions
    version: str     # hackmenot version
```

**Git-aware scanning:**
```bash
# New CLI flag
hackmenot scan . --changed-since main

# Only scans files changed since the given ref
git diff --name-only main...HEAD | hackmenot scan --stdin
```

### 3. Rule Execution Speed

**Compiled regex cache:**
```python
class CompiledPatternCache:
    """Cache compiled regex patterns across files."""
    _cache: dict[str, re.Pattern] = {}

    @classmethod
    def get(cls, pattern: str) -> re.Pattern:
        if pattern not in cls._cache:
            cls._cache[pattern] = re.compile(pattern)
        return cls._cache[pattern]
```

**Lazy rule loading:**
```python
def _load_rules_for_languages(self, languages: set[str]) -> None:
    """Only load rules for languages being scanned."""
    registry = RuleRegistry()
    for lang in languages:
        registry.load_for_language(lang)  # Lazy load
```

**Parser instance reuse:**
- Single parser instance per language type
- Already implemented, verify no per-file instantiation

## GitHub Action

### Usage

**Simple (one-liner):**
```yaml
- uses: b0rd3aux/hackmenot@v1
```

**Configurable:**
```yaml
- uses: b0rd3aux/hackmenot@v1
  with:
    paths: 'src/'
    severity: 'medium'
    fail-on: 'critical'
    format: 'sarif'
    include-deps: true
    comment: true
    cache: true
```

### Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `paths` | Paths to scan | `.` |
| `severity` | Minimum severity to report | `low` |
| `fail-on` | Severity threshold for failure | `high` |
| `format` | Output format (terminal, json, sarif) | `terminal` |
| `include-deps` | Scan dependency files | `false` |
| `comment` | Post PR comment with findings | `true` |
| `cache` | Use GitHub Actions cache | `true` |
| `changed-only` | Only scan changed files in PR | `true` |

### Outputs

| Output | Description |
|--------|-------------|
| `findings` | Number of findings |
| `critical` | Count of critical findings |
| `high` | Count of high findings |
| `sarif-file` | Path to SARIF output (if format=sarif) |

### Features

**PR Comments:**
- Summary comment with finding counts by severity
- Inline annotations on changed lines
- Collapsible details with code snippets

**SARIF Integration:**
```yaml
- uses: b0rd3aux/hackmenot@v1
  with:
    format: sarif
- uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: hackmenot-results.sarif
```

**Caching:**
- Uses `actions/cache` for `.hackmenot-cache/`
- Cache key includes: OS, Python version, hackmenot version
- Restores cache from previous runs for fast repeat scans

**Changed Files Only:**
- In pull requests, automatically detects changed files
- Only scans files in the PR diff
- Falls back to full scan on push to main

### Implementation

**File structure:**
```
action.yml          # Composite action definition
action/
  entrypoint.py     # Main script
  comment.py        # PR comment formatting
  requirements.txt  # Dependencies (hackmenot)
```

**action.yml (simplified):**
```yaml
name: 'hackmenot'
description: 'AI-Era Code Security Scanner'
branding:
  icon: 'shield'
  color: 'purple'

inputs:
  paths:
    description: 'Paths to scan'
    default: '.'
  # ... other inputs

runs:
  using: 'composite'
  steps:
    - uses: actions/setup-python@v5
      with:
        python-version: '3.11'

    - uses: actions/cache@v4
      with:
        path: ~/.hackmenot-cache
        key: hackmenot-${{ runner.os }}-${{ hashFiles('**/*.py') }}

    - run: pip install hackmenot
      shell: bash

    - run: python ${{ github.action_path }}/action/entrypoint.py
      shell: bash
      env:
        INPUT_PATHS: ${{ inputs.paths }}
        # ... other inputs
```

## Implementation Tasks

| # | Task | Description |
|---|------|-------------|
| 1 | Add SKIP_DIRS early filtering | Skip node_modules etc before extension check |
| 2 | Implement lazy file collection | Generator-based file discovery |
| 3 | Add --changed-since flag | Git-aware scanning for CI |
| 4 | Add cache versioning | Include rules hash in cache key |
| 5 | Implement compiled regex cache | Pre-compile patterns at startup |
| 6 | Add lazy rule loading | Load rules by language on demand |
| 7 | Create action.yml | GitHub Action definition |
| 8 | Create entrypoint.py | Action main script |
| 9 | Add PR comment support | Format and post findings |
| 10 | Add SARIF output integration | Upload to GitHub Security tab |
| 11 | Add GHA caching | Cache .hackmenot-cache between runs |
| 12 | Integration tests | Test action locally with act |
| 13 | Documentation | Update README with Action usage |

## Success Metrics

- **Large repo (10k files):** < 30 seconds cold, < 5 seconds warm
- **PR scan (50 changed files):** < 3 seconds
- **GitHub Action setup:** Single line in workflow
