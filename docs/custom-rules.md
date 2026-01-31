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
    # How to fix

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
