# CLI Reference

Complete reference for all hackmenot commands and options.

## Commands

### `hackmenot scan`

Scan code for security vulnerabilities.

```bash
hackmenot scan [PATHS...] [OPTIONS]
```

**Arguments:**
- `PATHS` - Files or directories to scan (default: current directory)

**Options:**
| Option | Description |
|--------|-------------|
| `--format, -f` | Output format: `terminal`, `json`, `sarif` |
| `--severity, -s` | Minimum severity to report: `critical`, `high`, `medium`, `low` |
| `--fail-on` | Minimum severity for non-zero exit: `critical`, `high`, `medium`, `low` |
| `--fix` | Automatically apply all available fixes |
| `--fix-interactive` | Interactively choose fixes to apply |
| `--full` | Bypass cache, perform full scan |
| `--ci` | CI-friendly output (no colors) |
| `--staged` | Scan only git staged files |
| `--pr-comment` | Output markdown for PR comments |
| `--include-deps` | Also scan dependency files |
| `--config, -c` | Path to config file |

**Examples:**
```bash
hackmenot scan .
hackmenot scan . --format sarif > results.sarif
hackmenot scan . --ci --fail-on critical
hackmenot scan --staged --ci
```

### `hackmenot deps`

Scan dependencies for security issues.

```bash
hackmenot deps PATH [OPTIONS]
```

**Arguments:**
- `PATH` - Directory containing dependency files

**Options:**
| Option | Description |
|--------|-------------|
| `--check-vulns` | Check for CVEs via OSV API (requires internet) |
| `--format, -f` | Output format: `terminal`, `json`, `sarif` |
| `--fail-on` | Minimum severity for non-zero exit |
| `--ci` | CI-friendly output |

**Examples:**
```bash
hackmenot deps .
hackmenot deps . --check-vulns
hackmenot deps . --check-vulns --ci --fail-on high
```

### `hackmenot rules`

List available security rules.

```bash
hackmenot rules [RULE_ID]
```

**Examples:**
```bash
hackmenot rules
hackmenot rules INJ001
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success, no findings at or above fail level |
| 1 | Findings at or above fail level |
| 2 | Error during scan |
