# hackmenot - AI-Era Code Security Scanner

## Design Document

**Date:** 2026-01-30
**Status:** Approved

---

## 1. Product Overview

### One-liner
A fast, developer-friendly security scanner that catches the vulnerabilities AI coding assistants commonly introduce.

### Core Insight
40-62% of AI-generated code contains security flaws. Traditional SAST tools weren't built for the patterns AI produces—missing auth checks, hardcoded secrets, hallucinated dependencies, weak crypto defaults. hackmenot applies AI-aware security rules to all code, providing not just warnings but fixes and education.

### Key Differentiators
- **AI-aware rules** - Purpose-built for vulnerabilities AI assistants commonly introduce
- **Fix, don't nag** - Every finding includes auto-fix suggestions, not just complaints
- **Developer education** - Explains *why* AI makes this mistake and how to prompt better
- **Sub-second scans** - Incremental scanning makes pre-commit hooks instant
- **Zero config** - Works immediately on any Python or JS/TS project

### Target Users
- Individual developers using Copilot, Cursor, Claude Code
- DevSecOps teams wanting CI/CD security gates
- Security-conscious startups shipping fast with AI assistance
- Enterprises needing audit trails for AI-assisted development

### Business Model
Open source CLI (Apache 2.0), optional cloud service for teams needing dashboards, policy management, and analytics.

---

## 2. Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        INTEGRATIONS                              │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────────────┐ │
│  │   CLI   │  │ VS Code │  │ GitHub  │  │ Pre-commit Hook     │ │
│  │         │  │Extension│  │ Action  │  │                     │ │
│  └────┬────┘  └────┬────┘  └────┬────┘  └──────────┬──────────┘ │
└───────┼────────────┼────────────┼──────────────────┼────────────┘
        │            │            │                  │
        └────────────┴─────┬──────┴──────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                      CORE ENGINE                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │   Scanner    │  │    Rules     │  │    Fix Engine          │ │
│  │   Engine     │◄─┤    Engine    │  │  (Templates + LLM)     │ │
│  └──────┬───────┘  └──────────────┘  └────────────────────────┘ │
│         │                                                        │
│  ┌──────▼───────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │   Parser     │  │    Cache     │  │    Reporter            │ │
│  │ (Python/JS)  │  │   Manager    │  │ (Terminal/SARIF/JSON)  │ │
│  └──────────────┘  └──────────────┘  └────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Core Components

1. **Scanner Engine** - Orchestrates file discovery, caching, parallel execution
2. **Parser** - Language-specific AST parsing (Python `ast`, TypeScript `tree-sitter`)
3. **Rules Engine** - Loads and executes vulnerability detection rules
4. **Fix Engine** - Generates fixes via templates or optional LLM
5. **Cache Manager** - File hashing, result caching for incremental scans
6. **Reporter** - Formats output (terminal, SARIF, JSON, HTML)

### Design Principles
- Each component is independently testable
- Rules are data-driven (YAML), not hardcoded
- Language parsers are pluggable for future expansion

---

## 3. Rules Engine

### Rule Definition Format (YAML)

```yaml
id: AUTH001
name: missing-auth-decorator
severity: high
category: authentication
languages: [python]
description: "Route handler missing authentication decorator"
ai_context: "AI often generates Flask/FastAPI routes without auth, assuming happy path"

pattern:
  type: ast
  match: function_with_decorator
  where:
    - has_decorator: ["app.route", "router.get", "router.post"]
    - missing_decorator: ["login_required", "auth_required", "Depends(get_current_user)"]
    - not_in_path: ["health", "ping", "public"]

fix:
  template: |
    @login_required
    {original}

message: "Endpoint '{function_name}' has no authentication. AI assistants often skip auth for simplicity."

education: |
  AI coding tools frequently generate "working" endpoints without security.
  Always prompt: "Add authentication using [your auth pattern]"

references:
  - https://owasp.org/API-Security/
```

### Vulnerability Categories (Launch)

| Category | Example Rules | Count |
|----------|---------------|-------|
| **Authentication** | Missing auth decorators, broken access control, session misconfig | ~15 |
| **Input Validation** | SQL injection, XSS, command injection, path traversal | ~20 |
| **Cryptography** | Weak algorithms (MD5/SHA1), hardcoded keys, insecure random | ~12 |
| **Data Exposure** | Logging secrets, verbose errors, debug mode in prod | ~10 |
| **Dependencies** | Hallucinated packages, typosquats, known vulnerable versions | ~8 |

**Total launch rules: ~65** across Python and JS/TS

---

## 4. CLI Interface

### Command Structure

```bash
# Basic usage - zero config
hackmenot scan .
hackmenot scan src/ tests/

# Output formats
hackmenot scan . --format terminal|sarif|json|html

# Fix modes
hackmenot scan . --suggest            # show fixes (default)
hackmenot scan . --fix-interactive    # prompt before each fix
hackmenot scan . --fix                # auto-apply safe fixes

# Performance
hackmenot scan . --full               # ignore cache, scan everything
hackmenot scan . --diff HEAD~1        # only scan changed files

# Filtering
hackmenot scan . --severity high,critical
hackmenot scan . --category auth,crypto
hackmenot scan . --ignore-path "tests/*"

# Other
hackmenot init                        # create .hackmenot.yml
hackmenot rules list                  # show all rules
hackmenot rules show AUTH001          # rule details
```

### Color Scheme

| Element | Color | Style |
|---------|-------|-------|
| Tool name | Cyan | Bold |
| File paths | Cyan | Normal |
| Line numbers | Magenta | Normal |
| Rule IDs | Yellow | Normal |
| Critical severity | Red | Bold + BG |
| High severity | Orange | Bold |
| Medium severity | Yellow | Bold |
| Low severity | Green | Dim |
| Code (issue line) | White | Yellow BG |
| Code (context) | White | Dim |
| Fix suggestions | Green | Bold label |
| Education | Blue label | Gray italic |
| Hotkeys | Cyan | Bold |
| Commands | Cyan | Normal |

---

## 5. Configuration

### Config File (`.hackmenot.yml`)

```yaml
fail_on: high  # critical | high | medium | low | none

rules:
  enable: [all]
  disable: [CRYPTO003]
  severity_override:
    DEP001: critical

paths:
  include: [src/, lib/]
  exclude: ["**/test_*.py", "vendor/"]

languages:
  python:
    version: "3.11"
  javascript:
    frameworks: [react, express]

fixes:
  auto_apply: [safe]
  llm:
    enabled: false
    provider: openai

output:
  format: terminal
  color: auto
  verbose: false
```

### Inline Ignores

```python
# Single line
password = "dev-only"  # hackmenot:ignore[CRYPTO004] - dev fixture

# Next line
# hackmenot:ignore[AUTH001] - public health endpoint
@app.route("/health")
def health():
    return "ok"

# Block
# hackmenot:ignore-start[INJ002]
legacy_query = f"SELECT * FROM {table}"
# hackmenot:ignore-end

# Entire file (top of file)
# hackmenot:ignore-file - generated code
```

**Rule:** Reason after `-` is required. No silent ignores.

---

## 6. Integrations

### GitHub Action

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  hackmenot:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hackmenot/action@v1
        with:
          fail_on: high
          format: sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: hackmenot-results.sarif
```

### Pre-commit Hook

```yaml
repos:
  - repo: https://github.com/hackmenot/hackmenot
    rev: v1.0.0
    hooks:
      - id: hackmenot
        args: [--fail-on, high, --diff, HEAD]
```

### VS Code Extension (Phase 2)
- Real-time scanning as you type
- Squiggly underlines (red=critical, yellow=warning)
- Quick Fix menu applies fixes
- Hover shows education tooltip

---

## 7. Dependency Scanning

### Detection Rules

| Check | Description | Severity |
|-------|-------------|----------|
| **DEP001** | Package doesn't exist on PyPI/npm | Critical |
| **DEP002** | Typosquat (Levenshtein ≤2 from popular) | Critical |
| **DEP003** | Low downloads + recent creation | High |
| **DEP004** | Deprecated/abandoned package | Medium |
| **DEP005** | Known vulnerable version (CVE) | Varies |

### Package Cache

```
~/.hackmenot/
  └── package-cache/
      ├── pypi-index.db
      ├── npm-index.db
      └── vulns.db
```

Offline mode works with cached data, warns if >7 days old.

---

## 8. Project Structure

```
hackmenot/
├── pyproject.toml
├── README.md
├── LICENSE                     # Apache 2.0
├── CLAUDE.md
│
├── src/hackmenot/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli/
│   │   ├── main.py             # Typer CLI
│   │   ├── commands.py
│   │   └── output.py           # Rich formatting
│   ├── core/
│   │   ├── scanner.py
│   │   ├── cache.py
│   │   └── config.py
│   ├── parsers/
│   │   ├── base.py
│   │   ├── python.py
│   │   └── javascript.py
│   ├── rules/
│   │   ├── engine.py
│   │   ├── registry.py
│   │   └── builtin/            # YAML rules
│   ├── fixes/
│   │   ├── engine.py
│   │   ├── templates.py
│   │   └── llm.py
│   ├── reporters/
│   │   ├── terminal.py
│   │   ├── sarif.py
│   │   ├── json.py
│   │   └── html.py
│   └── deps/
│       ├── scanner.py
│       ├── registries.py
│       └── cache.py
│
├── tests/
│   └── fixtures/
│
├── integrations/
│   ├── github-action/
│   └── pre-commit-hook/
│
└── docs/plans/
```

### Key Dependencies
- `typer` + `rich` - CLI and output
- `tree-sitter` - Multi-language parsing
- `pyyaml` - Rule definitions
- `httpx` - Async HTTP
- `pytest` - Testing

---

## 9. Implementation Phases

### Phase 1: Core MVP (Week 1-2)
- Project setup (pyproject.toml, CI)
- CLI skeleton with Typer
- Python AST parser
- Rules engine + 10 initial rules
- Terminal reporter with colors
- Basic caching
- JSON output

### Phase 2: Full Python + Fixes (Week 3-4)
- Complete Python ruleset (~35 rules)
- Fix engine with templates
- Fix modes (interactive, auto)
- SARIF output
- Config file support
- Inline ignores
- Incremental scanning
- Parallel processing

### Phase 3: JavaScript/TypeScript (Week 5-6)
- Tree-sitter JS/TS parser
- JS/TS rules (~30 rules)
- Framework-specific rules
- npm dependency scanning
- HTML reports

### Phase 4: Dependencies & Integrations (Week 7-8)
- PyPI/npm registry integration
- Hallucinated package detection
- Typosquat detection
- GitHub Action
- Pre-commit hook
- Documentation

### Phase 5: Polish & Extras (Post-launch)
- VS Code extension
- LLM-powered fixes
- More languages
- Cloud dashboard

---

## 10. Success Metrics

| Metric | Target |
|--------|--------|
| Scan speed | <1s for 100 files (incremental) |
| Rules | 65+ across 5 categories |
| False positive rate | <10% |
| Install to first scan | <30 seconds |
| GitHub stars | 500+ first month |

---

## Appendix: Terminal Output Example

```
$ hackmenot scan .

  🛡️  hackmenot v1.0.0 - AI-Era Code Security Scanner
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Scanning 142 files...

  ┌─────────────────────────────────────────────────────┐
  │ ✗ CRITICAL   src/api/users.py:45                    │
  │   AUTH001: Endpoint missing authentication          │
  └─────────────────────────────────────────────────────┘

       44 │   @app.route("/users/<id>")
    →  45 │   def get_user(id):
       46 │       return db.query(User).get(id)

    💡 Fix:  Add @login_required decorator
    📚 Why:  AI often generates routes without auth

    [f] Apply fix  [s] Skip  [i] Ignore rule

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  📊 Summary
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Files scanned:  142                     Time: 0.8s

  🔴 Critical: 3    🟠 High: 5    🟡 Medium: 12    🟢 Low: 2

  → Run hackmenot scan . --fix-interactive to fix issues
```
