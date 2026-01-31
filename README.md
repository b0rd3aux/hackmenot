<div align="center">

# 🛡️ hackmenot

**AI-Era Code Security Scanner**

*Catches the vulnerabilities AI coding assistants introduce—and fixes them.*

[![PyPI](https://img.shields.io/pypi/v/hackmenot?color=blue)](https://pypi.org/project/hackmenot/)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue)](https://github.com/b0rd3aux/hackmenot/pkgs/container/hackmenot)
[![Tests](https://img.shields.io/github/actions/workflow/status/b0rd3aux/hackmenot/hackmenot.yml?label=tests)](https://github.com/b0rd3aux/hackmenot/actions)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue)](https://www.python.org/downloads/)

![100+ Security Rules](https://img.shields.io/badge/rules-100+-green)
![4 Languages](https://img.shields.io/badge/languages-Python%20%7C%20JS%20%7C%20Go%20%7C%20Terraform-orange)
![Sub-second Scans](https://img.shields.io/badge/scans-sub--second-purple)

<img src="assets/hero-scan.gif" alt="hackmenot in action" width="700">

</div>

---

## The Problem

**Over 50% of AI-generated code contains security vulnerabilities.** Copilot, Cursor, and Claude Code are transforming how we write software—but they're also introducing patterns that traditional SAST tools weren't built to catch.

hackmenot is purpose-built for the AI era: it detects these vulnerabilities, provides **auto-fix suggestions**, and explains **why AI makes these mistakes** so you learn as you secure.

---

## Quick Start

Get scanning in 30 seconds:

```bash
# Install via pip
pip install hackmenot

# Or with Docker
docker pull ghcr.io/b0rd3aux/hackmenot:latest

# Scan your code
hackmenot scan .

# Scan with auto-fix
hackmenot scan . --fix

# Scan dependencies for hallucinated packages
hackmenot deps .
```

That's it. No config files, no setup, no API keys.

---

## Features

### Scan & Detect

100+ security rules purpose-built for AI-generated code patterns across Python, JavaScript/TypeScript, Go, and Terraform.

<img src="assets/hero-scan.gif" alt="hackmenot scanning code" width="700">

### Auto-Fix

Don't just find problems—fix them. Interactive mode lets you review and apply fixes one by one.

```bash
hackmenot scan . --fix-interactive
```

<img src="assets/fix-interactive.gif" alt="Auto-fix in action" width="700">

### Dependency Scanning

Detect hallucinated packages (dependencies that don't exist), typosquats, and known CVEs.

```bash
hackmenot deps . --check-vulns
```

<img src="assets/deps-scan.gif" alt="Dependency scanning" width="700">

### CI/CD & GitHub Security

Native GitHub Action with SARIF support. Findings appear directly in GitHub's Security tab.

```yaml
- uses: hackmenot/hackmenot@v1
  with:
    sarif-upload: 'true'
```

---

## What It Catches

| Category | Examples | Languages |
|----------|----------|-----------|
| **Injection** | SQL injection, command injection, XSS, path traversal | All |
| **Authentication** | Missing auth decorators, weak sessions, hardcoded credentials | Python, JS |
| **Cryptography** | Weak algorithms, hardcoded keys, insecure random | All |
| **Data Exposure** | Logging secrets, verbose errors, debug mode in prod | All |
| **Infrastructure** | Open security groups, missing encryption, public S3 buckets | Terraform |
| **Dependencies** | Hallucinated packages, typosquats, known CVEs | Python, JS |

---

## Installation

**pip (recommended)**
```bash
pip install hackmenot
```

**Docker**
```bash
# Pull image
docker pull ghcr.io/b0rd3aux/hackmenot:latest

# Scan current directory
docker run --rm -v $(pwd):/workspace ghcr.io/b0rd3aux/hackmenot scan .
```

**From source**
```bash
pip install git+https://github.com/b0rd3aux/hackmenot.git@v1.0.0
```

Requires Python 3.10+

## Usage

```bash
# Basic scan
hackmenot scan .

# Scan specific path
hackmenot scan src/

# Set minimum severity (critical, high, medium, low)
hackmenot scan . --severity medium

# Fail CI on high+ findings
hackmenot scan . --fail-on high

# Output as JSON or SARIF
hackmenot scan . --format json
hackmenot scan . --format sarif

# Auto-fix all issues
hackmenot scan . --fix

# Interactive fix mode
hackmenot scan . --fix-interactive

# Preview fixes without applying
hackmenot scan . --fix --dry-run --diff

# Scan only changed files (great for CI)
hackmenot scan . --changed-since origin/main

# Dependency scanning
hackmenot deps .
hackmenot deps . --check-vulns
```

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Getting Started](docs/getting-started.md) | First-time setup and basic usage |
| [CLI Reference](docs/cli-reference.md) | All commands and options |
| [Rules Reference](docs/rules-reference.md) | Complete list of 100+ security rules |
| [Configuration](docs/configuration.md) | `.hackmenot.yml` options |
| [CI Integration](docs/ci-integration.md) | GitHub Actions, GitLab, Jenkins, and more |
| [Custom Rules](docs/custom-rules.md) | Write your own security rules |
| [Contributing](docs/contributing.md) | How to contribute |

## Support

If hackmenot is useful to you, consider supporting its development:

[![Sponsor on Patreon](https://img.shields.io/badge/Patreon-Support-orange?logo=patreon)](https://patreon.com/b0rd3aux)

---

## Contributing

Contributions are welcome! See [Contributing Guide](docs/contributing.md) for details.

## License

Apache 2.0 - see [LICENSE](LICENSE) for details.
