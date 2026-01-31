# hackmenot

[![PyPI version](https://badge.fury.io/py/hackmenot.svg)](https://badge.fury.io/py/hackmenot)
[![Tests](https://github.com/hackmenot/hackmenot/actions/workflows/test.yml/badge.svg)](https://github.com/hackmenot/hackmenot/actions)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

AI-Era Code Security Scanner - catches the vulnerabilities AI coding assistants commonly introduce.

## Why hackmenot?

**40-62% of AI-generated code contains security flaws.** Traditional SAST tools weren't built for the patterns AI produces. hackmenot applies AI-aware security rules to all code, providing not just warnings but **fixes and education**.

## Features

- **100+ Security Rules** - Purpose-built for vulnerabilities Copilot, Cursor, Claude Code introduce
- **Fix, Don't Nag** - Every finding includes auto-fix suggestions
- **Developer Education** - Explains *why* AI makes this mistake
- **Dependency Scanning** - Detects hallucinated packages and typosquats
- **Sub-second Scans** - Incremental scanning makes pre-commit hooks instant
- **Zero Config** - Works immediately on Python, JavaScript/TypeScript, Go, and Terraform

## Quick Start

```bash
pip install hackmenot

# Scan your code
hackmenot scan .

# Scan dependencies
hackmenot deps .

# Auto-fix issues
hackmenot scan . --fix-interactive
```

## What It Catches

| Category | Examples |
|----------|----------|
| **Injection** | SQL injection, command injection, XSS |
| **Authentication** | Missing auth decorators, weak sessions |
| **Cryptography** | Weak algorithms, hardcoded keys |
| **Data Exposure** | Logging secrets, verbose errors |
| **Dependencies** | Hallucinated packages, typosquats, CVEs |

### Example

```
$ hackmenot scan .

CRITICAL  INJ001  src/api.py:42
  SQL injection: query built with f-string interpolation

  query = f"SELECT * FROM users WHERE id = {user_id}"

  Fix: Use parameterized queries:
       cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

Found 1 issue in 15 files (125ms)
```

## CI/CD Integration

### GitHub Actions

```yaml
- uses: hackmenot/hackmenot-action@v1
  with:
    fail-on: high
```

### Pre-commit

```yaml
repos:
  - repo: https://github.com/hackmenot/hackmenot
    rev: v0.1.0
    hooks:
      - id: hackmenot
```

See [CI Integration Guide](docs/ci-integration.md) for GitLab, Jenkins, and more.

## Documentation

- [Getting Started](docs/getting-started.md)
- [CLI Reference](docs/cli-reference.md)
- [Rules Reference](docs/rules-reference.md)
- [Configuration](docs/configuration.md)
- [CI Integration](docs/ci-integration.md)
- [Custom Rules](docs/custom-rules.md)
- [Contributing](docs/contributing.md)

## License

Apache 2.0
