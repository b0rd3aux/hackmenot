# Rules Reference

hackmenot includes 55+ security rules across multiple categories.

## Categories

| Category | Description | Rule Count |
|----------|-------------|------------|
| Injection | SQL, command, code injection | 11 |
| Authentication | Missing auth, weak passwords | 8 |
| Cryptography | Weak algorithms, hardcoded keys | 10 |
| Data Exposure | Logging secrets, verbose errors | 7 |
| XSS | Cross-site scripting | 4 |
| Validation | Input validation issues | 8 |
| Dependencies | Hallucinated packages, CVEs | 3 |

## Injection Rules

### INJ001 - SQL Injection (f-string)
- **Severity:** Critical
- **Languages:** Python
- **Description:** SQL query built using f-string with user input

```python
# Bad
query = f"SELECT * FROM users WHERE id = {user_id}"

# Good
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

### JSIJ001 - eval() Injection
- **Severity:** Critical
- **Languages:** JavaScript
- **Description:** Use of eval() with potentially untrusted input

```javascript
// Bad
eval(userInput);

// Good
JSON.parse(userInput);
```

## Dependency Rules

### DEP001 - Hallucinated Package
- **Severity:** High
- **Description:** Package not found in registry (may be AI-invented)

### DEP002 - Typosquat Package
- **Severity:** Critical
- **Description:** Package name similar to popular package

### DEP003 - Vulnerable Dependency
- **Severity:** Varies
- **Description:** Package has known CVE

## Listing All Rules

```bash
hackmenot rules
hackmenot rules INJ001
```
