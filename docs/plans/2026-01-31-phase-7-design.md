# Phase 7: Enhanced Auto-Fix - Design Document

## Overview

Transform auto-fix from simple line replacement to intelligent code transformation with full rule coverage and safe preview mode.

**Three pillars:**
1. **Smart Fixes** - Pattern-based transformations that understand code structure
2. **Template Coverage** - Every fixable rule gets an actionable fix
3. **Diff Preview** - `--dry-run` mode shows changes before applying

## Smart Fix Pattern Format

Instead of multiple fix "types", use a single smart fix template with context-aware placeholders.

### Current (comment-based suggestion)

```yaml
fix_template: "Use parameterized queries"
```

### New (pattern-based transformation)

```yaml
fix:
  pattern: 'db.Query("{sql}" + {var})'
  replacement: 'db.Query("{sql}", {var})'
```

### How It Works

1. `pattern` matches the vulnerable code using semantic placeholders
2. `replacement` rewrites it using captured groups
3. Engine handles indentation, multi-line, language syntax automatically

### Placeholder Types

| Placeholder | Matches | Regex |
|-------------|---------|-------|
| `{var}` | Variable name | `(\w+)` |
| `{arg}` | Function argument | `(.+?)` |
| `{string}` | String literal | `(["'].*?["'])` |
| `{expr}` | Any expression | `(.+)` |
| `{func}` | Function/method name | `(\w+(?:\.\w+)*)` |

### Examples

**SQL Injection (Python)**
```yaml
fix:
  pattern: '{func}("SELECT * FROM {table} WHERE id = " + {var})'
  replacement: '{func}("SELECT * FROM {table} WHERE id = ?", {var})'
```

**MD5 → SHA256 (Python)**
```yaml
fix:
  pattern: 'hashlib.md5({arg})'
  replacement: 'hashlib.sha256({arg})'
```

**Terraform Public Bucket**
```yaml
fix:
  pattern: 'acl = "public-read"'
  replacement: 'acl = "private"'
```

**Go Weak Hash**
```yaml
fix:
  pattern: 'md5.Sum({arg})'
  replacement: 'sha256.Sum256({arg})'
```

### Backward Compatibility

If no `fix.pattern` exists, show `fix.template` as suggestion (existing behavior preserved).

## Diff Preview & Dry-Run Mode

### CLI Options

```bash
# Preview changes without applying
hackmenot scan . --fix --dry-run

# Show full unified diff
hackmenot scan . --fix --dry-run --diff
```

### Output Format

```diff
Found 3 fixable issues in 2 files

── src/auth.py ──────────────────────────────────
@@ -15,1 +15,1 @@
-    query = "SELECT * FROM users WHERE id = " + user_id
+    query = "SELECT * FROM users WHERE id = ?", user_id

@@ -23,1 +23,1 @@
-    hash = hashlib.md5(password.encode())
+    hash = hashlib.sha256(password.encode())

── main.tf ──────────────────────────────────────
@@ -8,1 +8,1 @@
-  acl = "public-read"
+  acl = "private"

Run without --dry-run to apply these fixes.
```

### Behavior

| Flag | Behavior |
|------|----------|
| `--dry-run` | Summary of what would change |
| `--dry-run --diff` | Full unified diff output |
| (none) | Apply changes (existing behavior) |

## Fix Coverage Prioritization

### Tier 1: Auto-fixable (deterministic transforms) ~40 rules

| Language | Rules | Example Fix |
|----------|-------|-------------|
| Python | INJ001, CRYPTO001-003 | Parameterized queries, sha256 |
| JavaScript | JSCR001, JSAU001-003 | crypto.randomUUID(), env vars |
| Go | GO_INJ001, GO_CRY001-003 | Prepared statements, sha256 |
| Terraform | TF_S3001-003, TF_ENC001-004 | acl=private, encrypted=true |

### Tier 2: Semi-auto (needs context) ~30 rules

| Rules | Why Semi-Auto |
|-------|---------------|
| AUTH001-003 | Which decorator depends on framework |
| GO_INJ002 | Command injection fix depends on use case |
| TF_IAM001-003 | Need to know correct permissions |

### Tier 3: Suggestion only (human judgment) ~32 rules

| Rules | Why Manual |
|-------|------------|
| Concurrency rules | Architecture decisions |
| XSS context-dependent | Output context varies |
| Business logic | Security vs functionality tradeoff |

## Fix Engine Implementation

### Enhanced FixEngine

```python
class FixEngine:
    def apply_fix(self, source: str, finding: Finding, rule: Rule) -> FixResult:
        fix_config = rule.fix

        if fix_config.pattern and fix_config.replacement:
            # Smart fix: pattern-based transformation
            return self._apply_pattern_fix(source, finding, fix_config)
        elif fix_config.template:
            # Legacy: line replacement with template
            return self._apply_template_fix(source, finding, fix_config)
        else:
            # No fix available
            return FixResult(applied=False, reason="no_fix_defined")
```

### Pattern Matching

```python
# Placeholders become regex capture groups
pattern: '{func}({arg})'     →  regex: r'(\w+(?:\.\w+)*)\((.+?)\)'
replacement: '{func}({arg})' →  uses captured \1, \2
```

### FixResult Dataclass

```python
@dataclass
class FixResult:
    applied: bool
    original: str | None = None
    fixed: str | None = None
    reason: str | None = None  # "success", "no_match", "no_fix_defined"
```

## Implementation Tasks

| # | Task | Description |
|---|------|-------------|
| 1 | Update Rule model | Add `fix.pattern` and `fix.replacement` fields |
| 2 | Pattern parser | Build placeholder-to-regex converter |
| 3 | Enhance FixEngine | Add `_apply_pattern_fix()` method |
| 4 | Diff generator | Create unified diff output formatter |
| 5 | CLI --dry-run | Add `--dry-run` and `--diff` flags |
| 6 | Python fixes | Add smart patterns to ~12 Python rules |
| 7 | JavaScript fixes | Add smart patterns to ~8 JavaScript rules |
| 8 | Go fixes | Add smart patterns to ~10 Go rules |
| 9 | Terraform fixes | Add smart patterns to ~10 Terraform rules |
| 10 | Integration tests | End-to-end fix application tests |
| 11 | Update docs | Document --dry-run, fix patterns |

## Summary

- **Smart pattern-based fixes** replace comment suggestions with actual code transformations
- **~40 rules** get auto-fixable patterns across 4 languages
- **--dry-run** mode lets users preview changes safely
- **Unified diff output** shows exactly what will change
- **Backward compatible** with existing fix_template suggestions
