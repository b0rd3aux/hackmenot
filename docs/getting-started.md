# Getting Started with hackmenot

hackmenot is an AI-era code security scanner that catches vulnerabilities commonly introduced by AI coding assistants.

## Installation

```bash
pip install hackmenot
```

## Quick Start

### Scan Your Code

```bash
# Scan current directory
hackmenot scan .

# Scan a specific file
hackmenot scan src/app.py

# Scan with JSON output
hackmenot scan . --format json
```

### Scan Dependencies

```bash
# Check for hallucinated and typosquatted packages
hackmenot deps .

# Also check for known vulnerabilities (requires internet)
hackmenot deps . --check-vulns
```

### Understanding Output

hackmenot reports findings with severity levels:

| Severity | Meaning |
|----------|---------|
| **CRITICAL** | Immediate security risk, fix now |
| **HIGH** | Significant vulnerability, prioritize |
| **MEDIUM** | Security concern, should be addressed |
| **LOW** | Minor issue, fix when convenient |

Example output:

```
hackmenot v0.1.0

Scanning 15 files...

CRITICAL  INJ001  src/api.py:42
  SQL injection: query built with f-string interpolation

  query = f"SELECT * FROM users WHERE id = {user_id}"

  Fix: Use parameterized queries instead:
       cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

Found 1 issue in 15 files (125ms)
```

### Auto-Fix Issues

```bash
# Automatically apply fixes
hackmenot scan . --fix

# Interactively choose which fixes to apply
hackmenot scan . --fix-interactive
```

## Next Steps

- [CLI Reference](cli-reference.md) - All commands and options
- [CI Integration](ci-integration.md) - Set up in your pipeline
- [Configuration](configuration.md) - Customize hackmenot
