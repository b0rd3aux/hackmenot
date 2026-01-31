# CI/CD Integration

Integrate hackmenot into your CI/CD pipeline.

## GitHub Actions

### Using the Action

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hackmenot/hackmenot-action@v1
        with:
          path: '.'
          fail-on: 'high'
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

### SARIF Upload

```yaml
- run: hackmenot scan . --format sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

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
