# Custom Rules

Create your own security rules using YAML.

## Rule Structure

```yaml
id: CUSTOM001
name: my-custom-rule
severity: high
category: custom
languages: [python]
description: "Description of what this rule detects"

pattern:
  type: fstring
  contains: ["dangerous_function"]

message: "Warning message shown to user"

fix:
  template: |
    # How to fix (shown as suggestion)
  pattern: 'hashlib.md5({arg})'        # Optional: pattern to match
  replacement: 'hashlib.sha256({arg})' # Optional: replacement

education: |
  Explanation of the vulnerability
```

## Pattern Types

### fstring
```yaml
pattern:
  type: fstring
  contains: ["SELECT", "INSERT", "DELETE"]
```

### call
```yaml
pattern:
  type: call
  contains: ["eval", "exec"]
```

### string
```yaml
pattern:
  type: string
  contains: ["password", "secret"]
```

## Auto-Fix Patterns

Rules can include pattern-based auto-fixes that automatically transform code.

### Fix Configuration

```yaml
fix:
  template: |
    # Suggestion shown if pattern doesn't match
  pattern: '{func}({arg})'
  replacement: '{func}_safe({arg})'
```

### Placeholders

| Placeholder | Matches | Example |
|-------------|---------|---------|
| `{var}` | Variable name | `user_id`, `data` |
| `{func}` | Function name | `hashlib.md5`, `db.query` |
| `{arg}` | Single argument | `password.encode()` |
| `{args}` | Multiple arguments | `a, b, c` |
| `{string}` | String literal | `"hello"`, `'world'` |
| `{expr}` | Any expression | `x + y` |
| `{num}` | Number | `1024`, `256` |

### Examples

**Weak hash to strong hash:**
```yaml
fix:
  template: "Use hashlib.sha256() instead"
  pattern: 'hashlib.md5({arg})'
  replacement: 'hashlib.sha256({arg})'
```

**Insecure TLS:**
```yaml
fix:
  template: "Set InsecureSkipVerify to false"
  pattern: 'InsecureSkipVerify: true'
  replacement: 'InsecureSkipVerify: false'
```

**Public S3 bucket:**
```yaml
fix:
  template: "Use private ACL"
  pattern: 'acl = "public-read"'
  replacement: 'acl = "private"'
```

## Adding Custom Rules

1. Create `.hackmenot/rules/` in your project
2. Add YAML rule files
3. hackmenot loads them automatically

```
myproject/
├── .hackmenot/
│   └── rules/
│       └── CUSTOM001.yml
├── src/
└── ...
```
