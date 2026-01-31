# Phase 5: Dependency Scanning + Documentation - Design Document

**Date:** 2026-01-31
**Status:** Approved

---

## 1. Overview

**Goal:** Add dependency security scanning (hallucinated packages, typosquatting, CVEs) and comprehensive documentation for v1.0 release.

**Key Features:**
- Detect hallucinated (non-existent) packages AI may have invented
- Detect typosquatted package names that could be malicious
- Optional CVE lookup via OSV API
- Full documentation set for v1.0

---

## 2. Dependency Scanning Architecture

### New CLI Commands

```bash
hackmenot deps .                    # Scan dependencies (offline checks)
hackmenot deps . --check-vulns      # Include online CVE lookup via OSV
hackmenot scan . --include-deps     # Run both code + dependency scan
```

### New Files

```
src/hackmenot/
├── deps/
│   ├── __init__.py
│   ├── scanner.py          # Main dependency scanner
│   ├── parser.py           # Parse requirements.txt, package.json, pyproject.toml
│   ├── hallucination.py    # Check packages exist in registry
│   ├── typosquat.py        # Detect similar-named packages
│   └── vulns.py            # OSV API client for CVE lookup
├── data/
│   ├── pypi_top50k.txt     # Top 50K PyPI package names (~1.2MB)
│   └── npm_top50k.txt      # Top 50K npm package names (~1.0MB)
```

### Detection Flow

1. Parse dependency files → extract package names + versions
2. Check each package against bundled top-50K list
3. If not found → flag as potential hallucination
4. Run Levenshtein distance against known packages → flag typosquats
5. If `--check-vulns` → query OSV API for CVEs

---

## 3. Detection Logic

### Hallucination Detection
- Package not in top-50K list
- Secondary check: quick PyPI/npm HEAD request if online
- Severity: **high** - likely a non-existent package

### Typosquatting Detection
- Levenshtein distance ≤ 2 from a popular package (top 5K)
- Example: `requets` → suggests `requests`
- Severity: **critical** - potential malicious package

### Vulnerability Detection (--check-vulns)
- Query OSV API with package name + version
- Map CVSS scores to severity: critical/high/medium/low
- Include CVE ID and fix version in output

### New Rule IDs

| ID | Name | Severity |
|----|------|----------|
| DEP001 | hallucinated-package | high |
| DEP002 | typosquat-package | critical |
| DEP003 | vulnerable-dependency | varies |

---

## 4. Package Database

### Data Files

```
src/hackmenot/data/
├── pypi_top50k.txt      # ~1.2MB - one package name per line
└── npm_top50k.txt       # ~1.0MB - one package name per line
```

### Generation

- PyPI: BigQuery public dataset or pypistats API (top by downloads)
- npm: npm registry API or npms.io download stats
- Generation script: `scripts/update-package-lists.py`

### Loading Strategy

- Lazy load on first `deps` command
- Load into `set()` for O(1) lookup
- Cache in memory for duration of scan

---

## 5. OSV API Integration

### Query Format

```python
# Single query
POST https://api.osv.dev/v1/query
{
  "package": {"name": "requests", "ecosystem": "PyPI"},
  "version": "2.25.0"
}

# Batch query (preferred)
POST https://api.osv.dev/v1/querybatch
{"queries": [
  {"package": {"name": "pkg1", "ecosystem": "PyPI"}, "version": "1.0"},
  {"package": {"name": "pkg2", "ecosystem": "npm"}, "version": "2.0"}
]}
```

### Error Handling

- Network timeout → warn user, continue with offline-only results
- API error → log warning, don't fail the scan
- Cache responses for 1 hour in `.hackmenot-cache/`

---

## 6. Documentation Structure

### Expanded README.md

- Badges (PyPI version, tests passing, license)
- Quick start (install, first scan, see results)
- Feature highlights with examples
- Link to full docs

### Docs Folder

```
docs/
├── getting-started.md      # Installation, first scan, understanding output
├── cli-reference.md        # All commands and flags with examples
├── ci-integration.md       # GitHub Actions, GitLab, Jenkins, pre-commit
├── rules-reference.md      # All 55+ rules with descriptions, examples
├── custom-rules.md         # How to write your own YAML rules
├── configuration.md        # hackmenot.yml options, ignore patterns
└── contributing.md         # Dev setup, running tests, adding rules
```

---

## 7. Success Criteria

| Feature | Target |
|---------|--------|
| Dependency parsing | requirements.txt, package.json, pyproject.toml |
| Hallucination detection | Flag packages not in top-50K |
| Typosquat detection | Flag packages within edit distance 2 of popular pkg |
| CVE lookup | OSV API integration with --check-vulns |
| Scan performance | <2s for typical project (offline mode) |
| Documentation | 7 docs covering all features |

---

## 8. Implementation Order

1. **Package database** - Generate and bundle top-50K lists
2. **Dependency parser** - Parse requirements.txt, package.json, pyproject.toml
3. **Hallucination detector** - Check against bundled list
4. **Typosquat detector** - Levenshtein distance checks
5. **OSV integration** - CVE lookup with --check-vulns
6. **CLI integration** - `deps` command, `--include-deps` flag
7. **Documentation** - All 7 docs + README update
8. **Integration tests** - End-to-end dependency scanning tests
