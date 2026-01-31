# Phase 4: CI/CD Integration - Design Document

**Date:** 2026-01-31
**Status:** Approved

---

## 1. Overview

**Goal:** Make hackmenot easy to integrate into any CI/CD pipeline with first-class support for major platforms.

**Key Features:**
- GitHub Action with SARIF upload and PR comments
- GitLab CI template with MR integration
- Pre-commit hook (staged files by default)
- Jenkins, CircleCI, Azure DevOps templates
- New CLI flags: `--staged`, `--ci`, `--pr-comment`

---

## 2. Architecture

```
hackmenot/
├── action.yml                    # GitHub Action definition
├── .github/
│   └── workflows/
│       └── hackmenot.yml        # Reusable workflow
├── ci-templates/
│   ├── .pre-commit-hooks.yaml   # Pre-commit config
│   ├── gitlab-ci.yml            # GitLab CI template
│   ├── Jenkinsfile              # Jenkins pipeline
│   ├── azure-pipelines.yml      # Azure DevOps
│   └── .circleci/config.yml     # CircleCI
└── src/hackmenot/
    └── cli/
        ├── main.py              # New flags
        └── ci.py                # CI helpers (PR comments, etc.)
```

---

## 3. New CLI Flags

### `--staged`
Scan only git staged files (for pre-commit hooks).

```bash
hackmenot scan --staged
```

### `--ci`
CI-friendly output mode:
- No colors/rich formatting
- Machine-readable exit codes
- Quiet unless findings

```bash
hackmenot scan . --ci
```

### `--pr-comment`
Output markdown suitable for PR/MR comments.

```bash
hackmenot scan . --pr-comment > comment.md
```

---

## 4. GitHub Action

### action.yml
```yaml
name: 'hackmenot Security Scan'
description: 'Scan code for AI-generated security vulnerabilities'
inputs:
  path:
    description: 'Path to scan'
    default: '.'
  fail-on:
    description: 'Fail on severity level'
    default: 'high'
  sarif:
    description: 'Upload SARIF to Code Scanning'
    default: 'true'
  comment:
    description: 'Post PR comment with findings'
    default: 'true'
runs:
  using: 'composite'
  steps:
    - run: pip install hackmenot
    - run: hackmenot scan ${{ inputs.path }} --ci --format sarif > results.sarif
    - uses: github/codeql-action/upload-sarif@v3
      if: inputs.sarif == 'true'
      with:
        sarif_file: results.sarif
```

### Reusable Workflow
```yaml
# .github/workflows/hackmenot.yml
name: hackmenot
on:
  workflow_call:
    inputs:
      path:
        type: string
        default: '.'
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hackmenot/hackmenot-action@v1
        with:
          path: ${{ inputs.path }}
```

---

## 5. GitLab CI

### Template
```yaml
# ci-templates/gitlab-ci.yml
hackmenot:
  image: python:3.11
  stage: test
  script:
    - pip install hackmenot
    - hackmenot scan . --ci --format sarif > gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

---

## 6. Pre-commit Hook

### Configuration
```yaml
# ci-templates/.pre-commit-hooks.yaml
- id: hackmenot
  name: hackmenot security scan
  entry: hackmenot scan --staged --ci
  language: python
  types: [python, javascript, typescript]
  pass_filenames: false
```

### User Setup
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/hackmenot/hackmenot
    rev: v0.1.0
    hooks:
      - id: hackmenot
```

---

## 7. Other CI Platforms

### Jenkins (Jenkinsfile)
```groovy
pipeline {
    agent any
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

### CircleCI
```yaml
version: 2.1
jobs:
  security-scan:
    docker:
      - image: python:3.11
    steps:
      - checkout
      - run: pip install hackmenot
      - run: hackmenot scan . --ci
```

### Azure DevOps
```yaml
trigger:
  - main
pool:
  vmImage: 'ubuntu-latest'
steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.11'
  - script: |
      pip install hackmenot
      hackmenot scan . --ci
    displayName: 'Security Scan'
```

---

## 8. PR Comment Format

```markdown
## 🔒 hackmenot Security Scan

**Found 3 issues** in 5 files scanned

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 2 |
| 🟡 Medium | 0 |

### Critical Issues

**INJ001** - SQL injection via f-string
`src/api.py:42`
```python
query = f"SELECT * FROM users WHERE id = {user_id}"
```

<details>
<summary>View all findings</summary>
...
</details>

---
*Scanned by [hackmenot](https://github.com/hackmenot/hackmenot) v0.1.0*
```

---

## 9. Implementation Order

1. **CLI flags** - Add `--staged`, `--ci`, `--pr-comment`
2. **GitHub Action** - action.yml + reusable workflow
3. **Pre-commit** - Hook configuration
4. **GitLab CI** - Template + MR integration
5. **Other platforms** - Jenkins, CircleCI, Azure DevOps
6. **Documentation** - Usage guides for each platform

---

## 10. Success Criteria

| Metric | Target |
|--------|--------|
| GitHub Action | Works with SARIF upload |
| Pre-commit | <2s for staged files |
| GitLab CI | SAST report generated |
| All platforms | Copy-paste templates work |
