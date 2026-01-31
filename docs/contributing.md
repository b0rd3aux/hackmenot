# Contributing to hackmenot

## Development Setup

```bash
git clone https://github.com/hackmenot/hackmenot.git
cd hackmenot
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Running Tests

```bash
pytest
pytest --cov=hackmenot
pytest tests/test_core/test_scanner.py
pytest -k "test_sql"
```

## Code Style

```bash
ruff check .
ruff format .
mypy src/hackmenot
```

## Adding a New Rule

1. Create YAML in `src/hackmenot/rules/builtin/<category>/`:

```yaml
id: CAT001
name: rule-name
severity: high
category: category
languages: [python]
description: "What this rule detects"

pattern:
  type: fstring
  contains: ["pattern"]

message: "Warning message"
```

2. Add tests:

```python
def test_cat001_detects_pattern(tmp_path):
    (tmp_path / "test.py").write_text('vulnerable_code')
    scanner = Scanner()
    result = scanner.scan([tmp_path])
    assert any(f.rule_id == "CAT001" for f in result.findings)
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make changes
4. Run tests: `pytest`
5. Run linting: `ruff check .`
6. Commit: `git commit -m "feat: add feature"`
7. Push and open PR

## Commit Messages

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation
- `test:` - Tests
- `refactor:` - Refactoring
