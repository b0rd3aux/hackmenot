# Configuration

Configure hackmenot using `hackmenot.yml` in your project root.

## Configuration File

```yaml
# hackmenot.yml

fail_on: high

disabled_rules:
  - CRYPTO003

exclude:
  - "tests/**"
  - "docs/**"
  - "**/migrations/**"

rule_paths:
  - .hackmenot/rules
```

## Options

### fail_on
```yaml
fail_on: critical  # Only fail on critical
fail_on: high      # Fail on high+ (default)
fail_on: medium    # Fail on medium+
fail_on: low       # Fail on any issue
```

### disabled_rules
```yaml
disabled_rules:
  - INJ001
  - AUTH001
```

### exclude
```yaml
exclude:
  - "tests/**"
  - "**/*.test.py"
  - "vendor/**"
```

## Inline Ignores

```python
query = f"SELECT * FROM {table}"  # hackmenot: ignore INJ001
eval(code)  # hackmenot: ignore
```

```javascript
eval(code); // hackmenot: ignore JSIJ001
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `HACKMENOT_CONFIG` | Path to config file |
| `NO_COLOR` | Disable colored output |
