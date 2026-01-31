# Phase 3: JavaScript/TypeScript Support - Design Document

**Date:** 2026-01-31
**Status:** Approved

---

## 1. Overview

**Goal:** Extend hackmenot to scan JavaScript and TypeScript code, covering both frontend (React) and backend (Node.js) security patterns.

**Key Features:**
- Tree-sitter based JavaScript/TypeScript parser
- Support for `.js`, `.ts`, `.mjs`, `.cjs`, `.jsx`, `.tsx` files
- 20 new security rules covering JS/TS vulnerabilities
- New XSS category for frontend-specific issues

---

## 2. Architecture

```
src/hackmenot/
├── parsers/
│   ├── base.py            (NEW - shared parser interface)
│   ├── python.py          (existing, refactor to use base)
│   └── javascript.py      (NEW - tree-sitter based)
├── rules/
│   └── builtin/
│       ├── injection/     (add JSIJ001-005)
│       ├── auth/          (add JSAU001-004)
│       ├── crypto/        (add JSCR001-003)
│       ├── xss/           (NEW: XSS001-004)
│       └── validation/    (add JSVA001-004)
└── core/
    └── scanner.py         (extend language detection)
```

---

## 3. New Components

### JavaScriptParser (`src/hackmenot/parsers/javascript.py`)
- Uses `tree-sitter` and `tree-sitter-javascript` for parsing
- Extracts: function calls, template literals, JSX elements, object properties
- Handles all supported extensions via single parser
- Returns `ParseResult` compatible with existing engine

### Language Detection
- Scanner detects language from file extension
- Mapping:
  - `.py` → python
  - `.js`, `.mjs`, `.cjs`, `.jsx` → javascript
  - `.ts`, `.tsx` → javascript (tree-sitter-javascript handles TS)

---

## 4. Dependencies

Add to `pyproject.toml`:
```toml
dependencies = [
    "tree-sitter>=0.21.0",
    "tree-sitter-javascript>=0.21.0",
]
```

---

## 5. New Rules (20 total)

### Injection (5 rules)
| ID | Name | Pattern | Severity |
|----|------|---------|----------|
| JSIJ001 | eval-injection | `eval()`, `new Function()` | critical |
| JSIJ002 | sql-template-literal | SQL in template literals | critical |
| JSIJ003 | command-injection | `child_process.exec` with template | critical |
| JSIJ004 | code-injection | `vm.runInContext` with user input | critical |
| JSIJ005 | nosql-injection | MongoDB query with user input | high |

### Auth (4 rules)
| ID | Name | Pattern | Severity |
|----|------|---------|----------|
| JSAU001 | hardcoded-secret | `apiKey = "..."`, `secret = "..."` | high |
| JSAU002 | jwt-no-verify | `jwt.decode` without verify | critical |
| JSAU003 | insecure-cookie | `cookie` without secure/httpOnly | medium |
| JSAU004 | weak-password-hash | `crypto.createHash('md5')` for passwords | high |

### Crypto (3 rules)
| ID | Name | Pattern | Severity |
|----|------|---------|----------|
| JSCR001 | math-random-security | `Math.random()` for tokens/secrets | high |
| JSCR002 | weak-crypto | `crypto.createCipher` (deprecated) | high |
| JSCR003 | hardcoded-iv | Hardcoded IV in encryption | high |

### XSS (4 rules) - NEW CATEGORY
| ID | Name | Pattern | Severity |
|----|------|---------|----------|
| XSS001 | innerhtml-injection | `.innerHTML = `, `.outerHTML = ` | high |
| XSS002 | dangerous-react | `dangerouslySetInnerHTML` | high |
| XSS003 | document-write | `document.write()` | medium |
| XSS004 | postmessage-origin | `postMessage` without origin check | medium |

### Validation (4 rules)
| ID | Name | Pattern | Severity |
|----|------|---------|----------|
| JSVA001 | prototype-pollution | `obj[userInput] = ` | high |
| JSVA002 | regex-dos | Vulnerable regex patterns | medium |
| JSVA003 | path-traversal | `path.join` with user input | high |
| JSVA004 | open-redirect | `res.redirect(req.query.url)` | high |

---

## 6. Parser Implementation

### Tree-sitter Setup
```python
import tree_sitter_javascript as tsjs
from tree_sitter import Language, Parser

class JavaScriptParser:
    def __init__(self):
        self.parser = Parser(Language(tsjs.language()))

    def parse_file(self, file_path: Path) -> ParseResult:
        source = file_path.read_bytes()
        tree = self.parser.parse(source)
        return self._extract_patterns(tree, source)
```

### Pattern Extraction
Extract these node types for rule matching:
- `call_expression` - function calls like `eval()`, `exec()`
- `template_string` - template literals with interpolation
- `jsx_element` - React JSX for XSS detection
- `assignment_expression` - assignments like `innerHTML = `
- `member_expression` - property access like `document.write`

---

## 7. Testing Strategy

- Unit tests for JavaScriptParser
- Tests for each new rule (20 rules × 2 tests = 40 new tests)
- Integration tests for JS/TS scanning
- Mixed codebase tests (Python + JS in same project)

Expected: ~50 new tests

---

## 8. Implementation Order

1. **Parser** - JavaScriptParser with tree-sitter
2. **Scanner** - Language detection, multi-language support
3. **Injection Rules** - JSIJ001-005
4. **Auth Rules** - JSAU001-004
5. **Crypto Rules** - JSCR001-003
6. **XSS Rules** - XSS001-004 (new category)
7. **Validation Rules** - JSVA001-004
8. **Integration** - End-to-end tests

---

## 9. Success Criteria

| Metric | Target |
|--------|--------|
| JS/TS parsing | All 6 extensions supported |
| Rules | 20 new JS rules with tests |
| Performance | <500ms for 100-file JS project |
| Compatibility | Existing Python scanning unchanged |
