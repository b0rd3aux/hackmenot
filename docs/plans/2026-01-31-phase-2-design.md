# Phase 2: Full Python + Fixes - Design Document

**Date:** 2026-01-31
**Status:** Approved

---

## 1. Overview

**Goal:** Make hackmenot fast, configurable, and produce actionable fixes.

**Key Features:**
- Incremental scanning (skip unchanged files)
- Parallel processing (ThreadPoolExecutor)
- Fix engine with template-based fixes
- Interactive fix mode (`--fix-interactive`)
- SARIF output for GitHub Code Scanning
- Config file support (`.hackmenot.yml`)
- Inline ignores with required reasons
- Expanded ruleset (~35 Python rules)

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      CLI (main.py)                          │
│  --fix-interactive | --fix | --config | --full (no cache)  │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                 Scanner (scanner.py)                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │ FileCache    │  │ ThreadPool   │  │ ConfigLoader │       │
│  │ (incremental)│  │ (parallel)   │  │ (.hackmenot) │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                 IgnoreHandler (NEW)                          │
│  Parses inline ignores: # hackmenot:ignore[RULE] - reason   │
└─────────────────────────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│              FixEngine (NEW) + Reporters                     │
│  Template-based fixes | SARIF output | Interactive prompts  │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. New Components

### ConfigLoader (`src/hackmenot/core/config.py`)
- Loads `.hackmenot.yml` from project root
- Falls back to `~/.config/hackmenot/config.yml` for global defaults
- Merges configs (project overrides global)
- Supports: `fail_on`, `rules.enable/disable`, `paths.include/exclude`, `severity_override`

### IgnoreHandler (`src/hackmenot/core/ignores.py`)
- Parses source files for ignore comments before rule checking
- Supports three patterns:
  - `# hackmenot:ignore[RULE_ID] - reason` (single line)
  - `# hackmenot:ignore-next-line[RULE_ID] - reason`
  - `# hackmenot:ignore-file - reason` (top of file)
- Returns set of `(line_number, rule_id)` tuples to skip

### FixEngine (`src/hackmenot/fixes/engine.py`)
- Takes a Finding and applies its `fix_template`
- Simple string replacement for now
- Returns modified source code or None if can't fix

### SARIFReporter (`src/hackmenot/reporters/sarif.py`)
- Outputs SARIF 2.1.0 format
- Includes: tool info, rules metadata, results with locations
- Compatible with GitHub Code Scanning upload

---

## 4. Performance

### Incremental Scanning
```python
def _scan_file(self, file_path: Path) -> list[Finding]:
    # Check cache first
    cached = self.cache.get(file_path)
    if cached is not None:
        return cached

    # Parse and check
    findings = self._do_scan(file_path)

    # Store in cache
    self.cache.store(file_path, findings)
    return findings
```

### Parallel Processing
```python
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan(self, paths: list[Path], ...) -> ScanResult:
    files = self._collect_files(paths)
    findings = []

    max_workers = min(32, (os.cpu_count() or 1) + 4)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(self._scan_file, f): f for f in files}
        for future in as_completed(futures):
            findings.extend(future.result())

    return ScanResult(...)
```

**CLI flag:** `--full` bypasses cache for full rescan

---

## 5. Fix Modes

### CLI Flags
- `--fix` - Auto-apply all safe fixes, no prompts
- `--fix-interactive` - Prompt for each finding

### Interactive Flow
```
╭──────────────────────────────────────────────────────────────╮
│ ✗ CRITICAL  src/api.py:42                                    │
╰──────────────────────────────────────────────────────────────╯
  INJ001: SQL injection via f-string

    → query = f"SELECT * FROM users WHERE id = {user_id}"

  Suggested fix:
    → query = "SELECT * FROM users WHERE id = ?"
    → cursor.execute(query, (user_id,))

  [a]pply  [s]kip  [A]pply all  [q]uit  (a/s/A/q):
```

### Behavior
- Reads file, applies fix template at the finding's line
- Writes file back only after user confirms (or auto with `--fix`)
- Tracks applied fixes for summary: "Applied 3 fixes, skipped 2"
- For `--fix` auto mode, only apply fixes marked `safe: true` in rule YAML

---

## 6. Expanded Rules (~35 total)

### Current 10 Rules
INJ001-002, AUTH001-002, CRYPTO001-002, EXP001-002, DEP001-002

### New 25 Rules by Category

| Category | New Rules | Examples |
|----------|-----------|----------|
| **Injection (+5)** | INJ003-007 | Path traversal, SSRF, XSS in templates, unsafe eval, code injection |
| **Authentication (+5)** | AUTH003-007 | Hardcoded passwords, weak session config, missing CSRF, JWT none algorithm, insecure cookie |
| **Cryptography (+5)** | CRYPTO003-007 | Weak random, ECB mode, small key size, hardcoded IV, no salt in hash |
| **Data Exposure (+5)** | EXP003-007 | Logging secrets, stack trace in response, .env in repo, sensitive in URL, verbose exceptions |
| **Input Validation (+5)** | VAL001-005 | Missing input length, regex DoS, type confusion, mass assignment, unsafe redirect |

**Total: 35 rules** (10 existing + 25 new)

Each rule includes `safe: true/false` for auto-fix eligibility.

---

## 7. Config File Format

### `.hackmenot.yml`
```yaml
fail_on: high  # Exit 1 if findings at this level or above

rules:
  disable: [DEP001, DEP002]  # Skip these rules
  severity_override:
    CRYPTO002: critical      # Treat SHA1 as critical for this project

paths:
  exclude:
    - "tests/*"
    - "migrations/*"
    - "vendor/*"

fixes:
  auto_apply_safe: true      # --fix applies safe fixes only
```

### Hierarchy
1. CLI flags (highest priority)
2. `.hackmenot.yml` in project root
3. `~/.config/hackmenot/config.yml` (global defaults)

---

## 8. Inline Ignores

### Syntax
```python
# Single line
password = "dev-only"  # hackmenot:ignore[CRYPTO004] - dev fixture

# Next line
# hackmenot:ignore-next-line[AUTH001] - public health endpoint
@app.route("/health")
def health():
    return "ok"

# Entire file (must be at top)
# hackmenot:ignore-file - generated code
```

**Rule:** Reason after `-` is required. No silent ignores.

---

## 9. Testing Strategy

- Unit tests for each new component (ConfigLoader, IgnoreHandler, FixEngine, SARIFReporter)
- Integration tests for parallel scanning, caching behavior
- Test fixtures with inline ignores
- SARIF output validation against schema
- ~20-25 new tests expected

---

## 10. Success Criteria

| Metric | Target |
|--------|--------|
| Incremental scan | <100ms for unchanged 100-file project |
| Rules | 35 total with tests |
| SARIF | Uploads to GitHub Code Scanning |
| Fix modes | Interactive and auto work correctly |

---

## 11. Implementation Order

1. **Performance** - Incremental scanning + parallel processing
2. **Config** - ConfigLoader + CLI integration
3. **Ignores** - IgnoreHandler + parser integration
4. **Fixes** - FixEngine + interactive mode
5. **SARIF** - SARIFReporter
6. **Rules** - 25 new rules (5 per category)
7. **Integration** - End-to-end tests
