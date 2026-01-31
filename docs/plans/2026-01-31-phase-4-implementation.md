# Phase 4: CI/CD Integration - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make hackmenot easy to integrate into any CI/CD pipeline.

**Architecture:** New CLI flags, GitHub Action, pre-commit hook, CI templates.

**Tech Stack:** Python, GitHub Actions, GitLab CI, pre-commit

---

## Task 1: Add --staged Flag for Git Staged Files

**Files:**
- Modify: `src/hackmenot/cli/main.py`
- Create: `src/hackmenot/cli/git.py`
- Create: `tests/test_cli/test_staged.py`

**Step 1: Create git.py helper**

```python
"""Git helpers for CI integration."""

import subprocess
from pathlib import Path


def get_staged_files() -> list[Path]:
    """Get list of staged files from git."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            capture_output=True,
            text=True,
            check=True,
        )
        files = [Path(f) for f in result.stdout.strip().split("\n") if f]
        return files
    except subprocess.CalledProcessError:
        return []


def is_git_repo() -> bool:
    """Check if current directory is a git repository."""
    try:
        subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            capture_output=True,
            check=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False
```

**Step 2: Add --staged flag to main.py**

```python
    staged: bool = typer.Option(
        False,
        "--staged",
        help="Scan only git staged files (for pre-commit hooks)",
    ),

# In scan command:
    if staged:
        from hackmenot.cli.git import get_staged_files, is_git_repo
        if not is_git_repo():
            console.print("[red]Error: --staged requires a git repository[/red]")
            raise typer.Exit(1)
        staged_files = get_staged_files()
        if not staged_files:
            console.print("[green]No staged files to scan[/green]")
            raise typer.Exit(0)
        paths = staged_files
```

**Step 3: Create tests**

```python
def test_staged_flag_scans_staged_files(tmp_path: Path):
    """Test --staged scans only staged files."""
    # Initialize git repo, stage a file, run scan --staged

def test_staged_flag_requires_git_repo(tmp_path: Path):
    """Test --staged fails outside git repo."""
```

**Step 4: Commit**

```bash
git commit -m "feat: add --staged flag for scanning git staged files"
```

---

## Task 2: Add --ci Flag for CI-Friendly Output

**Files:**
- Modify: `src/hackmenot/cli/main.py`
- Modify: `src/hackmenot/reporters/terminal.py`
- Create: `tests/test_cli/test_ci.py`

**Step 1: Add --ci flag**

```python
    ci: bool = typer.Option(
        False,
        "--ci",
        help="CI-friendly output (no colors, machine-readable exit codes)",
    ),

# Modify console creation:
    if ci:
        console = Console(force_terminal=False, no_color=True)
```

**Step 2: Update exit codes for CI**

- Exit 0: No findings at or above fail_on level
- Exit 1: Findings at or above fail_on level
- Exit 2: Error during scan

**Step 3: Create tests**

```python
def test_ci_flag_disables_colors(tmp_path: Path):
    """Test --ci disables ANSI colors."""

def test_ci_flag_exit_codes(tmp_path: Path):
    """Test --ci uses correct exit codes."""
```

**Step 4: Commit**

```bash
git commit -m "feat: add --ci flag for CI-friendly output"
```

---

## Task 3: Add --pr-comment Flag for PR Comments

**Files:**
- Create: `src/hackmenot/reporters/markdown.py`
- Modify: `src/hackmenot/cli/main.py`
- Create: `tests/test_reporters/test_markdown.py`

**Step 1: Create markdown reporter**

```python
"""Markdown reporter for PR comments."""

from hackmenot.core.models import Finding, ScanResult, Severity


class MarkdownReporter:
    """Generate markdown for PR comments."""

    SEVERITY_EMOJI = {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🟢",
    }

    def render(self, result: ScanResult) -> str:
        """Render scan results as markdown."""
        lines = []
        lines.append("## 🔒 hackmenot Security Scan\n")

        if not result.has_findings:
            lines.append("✅ **No security issues found!**\n")
        else:
            lines.append(f"**Found {len(result.findings)} issues** in {result.files_scanned} files\n")
            lines.append(self._severity_table(result))
            lines.append(self._findings_section(result))

        lines.append("\n---")
        lines.append("*Scanned by [hackmenot](https://github.com/hackmenot/hackmenot)*")

        return "\n".join(lines)
```

**Step 2: Add --pr-comment flag**

```python
    pr_comment: bool = typer.Option(
        False,
        "--pr-comment",
        help="Output markdown for PR comments",
    ),

# In scan command:
    if pr_comment:
        from hackmenot.reporters.markdown import MarkdownReporter
        reporter = MarkdownReporter()
        print(reporter.render(result))
        raise typer.Exit(0 if not result.has_findings else 1)
```

**Step 3: Commit**

```bash
git commit -m "feat: add --pr-comment flag for markdown output"
```

---

## Task 4: Create GitHub Action

**Files:**
- Create: `action.yml`
- Create: `.github/workflows/hackmenot.yml`
- Create: `ci-templates/github-action-example.yml`

**Step 1: Create action.yml**

```yaml
name: 'hackmenot Security Scan'
description: 'Scan code for AI-generated security vulnerabilities'
author: 'hackmenot'
branding:
  icon: 'shield'
  color: 'purple'

inputs:
  path:
    description: 'Path to scan'
    required: false
    default: '.'
  fail-on:
    description: 'Minimum severity to fail on (critical, high, medium, low)'
    required: false
    default: 'high'
  sarif:
    description: 'Upload SARIF results to GitHub Code Scanning'
    required: false
    default: 'true'

outputs:
  findings:
    description: 'Number of findings'
    value: ${{ steps.scan.outputs.findings }}

runs:
  using: 'composite'
  steps:
    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.11'

    - name: Install hackmenot
      shell: bash
      run: pip install hackmenot

    - name: Run scan
      id: scan
      shell: bash
      run: |
        hackmenot scan ${{ inputs.path }} --ci --fail-on ${{ inputs.fail-on }} --format sarif > hackmenot-results.sarif 2>&1 || true
        echo "findings=$(cat hackmenot-results.sarif | jq '.runs[0].results | length')" >> $GITHUB_OUTPUT

    - name: Upload SARIF
      if: inputs.sarif == 'true'
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: hackmenot-results.sarif
```

**Step 2: Create reusable workflow**

```yaml
# .github/workflows/hackmenot.yml
name: hackmenot Security Scan

on:
  workflow_call:
    inputs:
      path:
        type: string
        default: '.'
      fail-on:
        type: string
        default: 'high'

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: ./
        with:
          path: ${{ inputs.path }}
          fail-on: ${{ inputs.fail-on }}
```

**Step 3: Commit**

```bash
git commit -m "feat: add GitHub Action for hackmenot"
```

---

## Task 5: Create Pre-commit Hook

**Files:**
- Create: `.pre-commit-hooks.yaml`
- Create: `ci-templates/pre-commit-config.yaml`

**Step 1: Create .pre-commit-hooks.yaml**

```yaml
- id: hackmenot
  name: hackmenot security scan
  description: Scan staged files for security vulnerabilities
  entry: hackmenot scan --staged --ci
  language: python
  types_or: [python, javascript, ts, jsx, tsx]
  pass_filenames: false
  stages: [commit]

- id: hackmenot-all
  name: hackmenot full scan
  description: Scan all files for security vulnerabilities
  entry: hackmenot scan . --ci
  language: python
  types_or: [python, javascript, ts, jsx, tsx]
  pass_filenames: false
  stages: [push]
```

**Step 2: Create example config**

```yaml
# ci-templates/pre-commit-config.yaml
# Example .pre-commit-config.yaml for users
repos:
  - repo: https://github.com/hackmenot/hackmenot
    rev: v0.1.0
    hooks:
      - id: hackmenot
        # Optional: customize fail level
        args: ['--fail-on', 'high']
```

**Step 3: Commit**

```bash
git commit -m "feat: add pre-commit hook configuration"
```

---

## Task 6: Create GitLab CI Template

**Files:**
- Create: `ci-templates/gitlab-ci.yml`

**Step 1: Create template**

```yaml
# GitLab CI template for hackmenot
# Include in your .gitlab-ci.yml:
#   include:
#     - remote: 'https://raw.githubusercontent.com/hackmenot/hackmenot/main/ci-templates/gitlab-ci.yml'

hackmenot:
  image: python:3.11-slim
  stage: test
  before_script:
    - pip install --quiet hackmenot
  script:
    - hackmenot scan . --ci --fail-on ${HACKMENOT_FAIL_ON:-high} --format sarif > gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
    paths:
      - gl-sast-report.json
    when: always
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

# Optional: MR comment with findings
hackmenot:comment:
  image: python:3.11-slim
  stage: test
  needs: []
  before_script:
    - pip install --quiet hackmenot
  script:
    - hackmenot scan . --ci --pr-comment > comment.md
    - |
      if [ -s comment.md ]; then
        curl --request POST --header "PRIVATE-TOKEN: ${GITLAB_TOKEN}" \
          --data-urlencode "body@comment.md" \
          "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/merge_requests/${CI_MERGE_REQUEST_IID}/notes"
      fi
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  allow_failure: true
```

**Step 2: Commit**

```bash
git commit -m "feat: add GitLab CI template"
```

---

## Task 7: Create Jenkins, CircleCI, Azure DevOps Templates

**Files:**
- Create: `ci-templates/Jenkinsfile`
- Create: `ci-templates/circleci-config.yml`
- Create: `ci-templates/azure-pipelines.yml`

**Step 1: Create Jenkinsfile**

```groovy
// Jenkinsfile for hackmenot
// Add to your project root or reference from Jenkins

pipeline {
    agent {
        docker {
            image 'python:3.11-slim'
        }
    }

    environment {
        HACKMENOT_FAIL_ON = 'high'
    }

    stages {
        stage('Install') {
            steps {
                sh 'pip install hackmenot'
            }
        }

        stage('Security Scan') {
            steps {
                sh 'hackmenot scan . --ci --fail-on ${HACKMENOT_FAIL_ON}'
            }
        }
    }

    post {
        always {
            sh 'hackmenot scan . --ci --format sarif > hackmenot-results.sarif || true'
            archiveArtifacts artifacts: 'hackmenot-results.sarif', allowEmptyArchive: true
        }
    }
}
```

**Step 2: Create CircleCI config**

```yaml
# .circleci/config.yml
version: 2.1

executors:
  python:
    docker:
      - image: cimg/python:3.11

jobs:
  hackmenot-scan:
    executor: python
    steps:
      - checkout
      - run:
          name: Install hackmenot
          command: pip install hackmenot
      - run:
          name: Security Scan
          command: hackmenot scan . --ci --fail-on high
      - run:
          name: Generate SARIF
          command: hackmenot scan . --ci --format sarif > hackmenot-results.sarif
          when: always
      - store_artifacts:
          path: hackmenot-results.sarif

workflows:
  security:
    jobs:
      - hackmenot-scan
```

**Step 3: Create Azure Pipelines config**

```yaml
# azure-pipelines.yml
trigger:
  - main
  - develop

pool:
  vmImage: 'ubuntu-latest'

variables:
  HACKMENOT_FAIL_ON: 'high'

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.11'
    displayName: 'Use Python 3.11'

  - script: pip install hackmenot
    displayName: 'Install hackmenot'

  - script: hackmenot scan . --ci --fail-on $(HACKMENOT_FAIL_ON)
    displayName: 'Security Scan'

  - script: hackmenot scan . --ci --format sarif > $(Build.ArtifactStagingDirectory)/hackmenot-results.sarif
    displayName: 'Generate SARIF'
    condition: always()

  - publish: $(Build.ArtifactStagingDirectory)/hackmenot-results.sarif
    artifact: SecurityResults
    condition: always()
```

**Step 4: Commit**

```bash
git commit -m "feat: add Jenkins, CircleCI, Azure DevOps templates"
```

---

## Task 8: Integration Tests for CI Features

**Files:**
- Create: `tests/test_cli/test_ci_integration.py`

**Step 1: Create integration tests**

```python
"""Integration tests for CI features."""

def test_staged_scan_in_git_repo(tmp_path: Path):
    """Test --staged works in a git repository."""

def test_ci_output_has_no_ansi(tmp_path: Path):
    """Test --ci removes ANSI escape codes."""

def test_pr_comment_outputs_markdown(tmp_path: Path):
    """Test --pr-comment outputs valid markdown."""

def test_sarif_output_for_ci(tmp_path: Path):
    """Test SARIF output works with --ci flag."""

def test_exit_codes_for_ci(tmp_path: Path):
    """Test exit codes are correct for CI."""
```

**Step 2: Commit**

```bash
git commit -m "feat: add CI integration tests"
```

---

## Summary

**Total Tasks:** 8
**Expected Tests:** ~15 new tests
**New Files:** ~15 files (action, templates, helpers)

**Key Deliverables:**
1. `--staged` flag for pre-commit hooks
2. `--ci` flag for CI-friendly output
3. `--pr-comment` flag for markdown comments
4. GitHub Action with SARIF upload
5. Pre-commit hook configuration
6. GitLab CI template
7. Jenkins, CircleCI, Azure DevOps templates
8. Integration tests
