# CI/CD Integration

Integrate hackmenot into your CI/CD pipeline.

## GitHub Actions

### Quick Start

Add hackmenot to your workflow with a single line:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hackmenot/hackmenot@v1
```

### Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Path to scan (file or directory) | `.` |
| `severity` | Minimum severity to report (critical, high, medium, low) | `low` |
| `fail-on` | Minimum severity to fail the build | `high` |
| `format` | Output format (terminal, json, sarif) | `terminal` |
| `sarif-upload` | Upload SARIF to GitHub Security tab | `false` |
| `changed-only` | Only scan files changed in PR | `false` |
| `python-version` | Python version to use | `3.11` |

### Action Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Number of security findings detected |
| `sarif-file` | Path to SARIF file (when using SARIF format) |

### SARIF Integration

Upload results to GitHub Security tab for centralized vulnerability tracking:

```yaml
- uses: hackmenot/hackmenot@v1
  with:
    sarif-upload: 'true'
```

### Fast PR Scanning

Use `changed-only` to scan only files modified in the PR:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0  # Required for changed-only
- uses: hackmenot/hackmenot@v1
  with:
    changed-only: 'true'
```

### Manual Setup

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install hackmenot
      - run: hackmenot scan . --ci --fail-on high
```

### Manual SARIF Upload

```yaml
- run: hackmenot scan . --format sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Performance Tips

### Large Codebases

hackmenot automatically skips common non-source directories:
- `node_modules`, `vendor`, `third_party`
- `__pycache__`, `.git`, `.venv`
- `dist`, `build`, `.terraform`

### Incremental Scanning

For faster CI runs, scan only changed files:

```bash
# Scan files changed since main branch
hackmenot scan . --changed-since origin/main

# Scan staged files (for pre-commit hooks)
hackmenot scan --staged
```

### Cache Optimization

hackmenot caches scan results by file hash. The cache auto-invalidates when:
- File contents change
- Rules are updated
- hackmenot version changes

Use `--full` to bypass the cache for a complete rescan.

## GitLab CI

```yaml
hackmenot:
  image: python:3.11-slim
  stage: test
  script:
    - pip install hackmenot
    - hackmenot scan . --ci --fail-on high
```

## Pre-commit Hook

```yaml
repos:
  - repo: https://github.com/hackmenot/hackmenot
    rev: v0.1.0
    hooks:
      - id: hackmenot
```

## Jenkins

```groovy
pipeline {
    agent { docker { image 'python:3.11' } }
    stages {
        stage('Security Scan') {
            steps {
                sh 'pip install hackmenot'
                sh 'hackmenot scan . --ci --fail-on high'
            }
        }
    }
}
```

## CircleCI

```yaml
version: 2.1
jobs:
  security-scan:
    docker:
      - image: cimg/python:3.11
    steps:
      - checkout
      - run: pip install hackmenot
      - run: hackmenot scan . --ci --fail-on high
```

## Azure DevOps

```yaml
trigger: [main]
pool:
  vmImage: 'ubuntu-latest'
steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.11'
  - script: |
      pip install hackmenot
      hackmenot scan . --ci --fail-on high
    displayName: 'Security Scan'
```
