# hackmenot

AI-Era Code Security Scanner - catches the vulnerabilities AI coding assistants commonly introduce.

## Why hackmenot?

40-62% of AI-generated code contains security flaws. Traditional SAST tools weren't built for the patterns AI produces. hackmenot applies AI-aware security rules to all code, providing not just warnings but **fixes and education**.

## Features

- **AI-aware rules** - Purpose-built for vulnerabilities Copilot, Cursor, Claude Code commonly introduce
- **Fix, don't nag** - Every finding includes auto-fix suggestions
- **Developer education** - Explains *why* AI makes this mistake
- **Sub-second scans** - Incremental scanning makes pre-commit hooks instant
- **Zero config** - Works immediately on any Python or JS/TS project

## Quick Start

```bash
pip install hackmenot

# Scan current directory
hackmenot scan .

# Auto-fix issues interactively
hackmenot scan . --fix-interactive
```

## What It Catches

| Category | Examples |
|----------|----------|
| **Authentication** | Missing auth decorators, broken access control |
| **Input Validation** | SQL injection, XSS, command injection |
| **Cryptography** | Weak algorithms, hardcoded keys |
| **Data Exposure** | Logging secrets, verbose errors |
| **Dependencies** | Hallucinated packages, typosquats |

## Integrations

- **CLI** - Works anywhere
- **GitHub Action** - Block PRs with security issues
- **Pre-commit hook** - Catch issues before commit
- **VS Code** - Real-time scanning (coming soon)

## License

Apache 2.0
