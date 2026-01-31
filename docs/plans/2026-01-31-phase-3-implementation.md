# Phase 3: JavaScript/TypeScript Support - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add JavaScript/TypeScript scanning with 20 new security rules.

**Architecture:** Tree-sitter parser for JS/TS, scanner extended for multi-language, new XSS rule category.

**Tech Stack:** Python 3.11+, tree-sitter, tree-sitter-javascript

---

## Task 1: Add Tree-sitter Dependencies

**Files:**
- Modify: `pyproject.toml`

**Step 1: Update pyproject.toml**

Add tree-sitter dependencies:
```toml
dependencies = [
    "typer>=0.9.0",
    "rich>=13.0.0",
    "pyyaml>=6.0",
    "tree-sitter>=0.21.0",
    "tree-sitter-javascript>=0.21.0",
]
```

**Step 2: Install dependencies**

```bash
pip install -e .
```

**Step 3: Verify installation**

```bash
python -c "import tree_sitter; import tree_sitter_javascript; print('OK')"
```

**Step 4: Commit**

```bash
git add pyproject.toml
git commit -m "feat: add tree-sitter dependencies for JS/TS parsing"
```

---

## Task 2: Create JavaScriptParser

**Files:**
- Create: `src/hackmenot/parsers/javascript.py`
- Modify: `src/hackmenot/parsers/__init__.py`
- Create: `tests/test_parsers/test_javascript.py`

**Step 1: Write failing tests**

Create `tests/test_parsers/test_javascript.py`:
```python
"""Tests for JavaScript parser."""

from pathlib import Path

from hackmenot.parsers.javascript import JavaScriptParser


def test_parser_can_parse_js_file(tmp_path: Path):
    """Test parser can parse a JavaScript file."""
    js_file = tmp_path / "test.js"
    js_file.write_text('const x = 1;')

    parser = JavaScriptParser()
    result = parser.parse_file(js_file)

    assert not result.has_error


def test_parser_extracts_function_calls(tmp_path: Path):
    """Test parser extracts function calls."""
    js_file = tmp_path / "test.js"
    js_file.write_text('eval("code"); console.log("test");')

    parser = JavaScriptParser()
    result = parser.parse_file(js_file)

    assert len(result.calls) >= 2
    call_names = [c.name for c in result.calls]
    assert "eval" in call_names


def test_parser_extracts_template_literals(tmp_path: Path):
    """Test parser extracts template literals."""
    js_file = tmp_path / "test.js"
    js_file.write_text('const query = `SELECT * FROM ${table}`;')

    parser = JavaScriptParser()
    result = parser.parse_file(js_file)

    assert len(result.template_literals) >= 1


def test_parser_extracts_assignments(tmp_path: Path):
    """Test parser extracts assignments."""
    js_file = tmp_path / "test.js"
    js_file.write_text('element.innerHTML = userInput;')

    parser = JavaScriptParser()
    result = parser.parse_file(js_file)

    assert len(result.assignments) >= 1


def test_parser_handles_jsx(tmp_path: Path):
    """Test parser handles JSX syntax."""
    jsx_file = tmp_path / "test.jsx"
    jsx_file.write_text('<div dangerouslySetInnerHTML={{__html: html}} />')

    parser = JavaScriptParser()
    result = parser.parse_file(jsx_file)

    assert not result.has_error


def test_parser_handles_typescript(tmp_path: Path):
    """Test parser handles TypeScript."""
    ts_file = tmp_path / "test.ts"
    ts_file.write_text('const x: number = 1;')

    parser = JavaScriptParser()
    result = parser.parse_file(ts_file)

    assert not result.has_error


def test_parser_handles_syntax_error(tmp_path: Path):
    """Test parser handles syntax errors gracefully."""
    js_file = tmp_path / "test.js"
    js_file.write_text('const x = {')

    parser = JavaScriptParser()
    result = parser.parse_file(js_file)

    assert result.has_error
```

**Step 2: Create JavaScriptParser**

Create `src/hackmenot/parsers/javascript.py`:
```python
"""JavaScript/TypeScript parser using tree-sitter."""

from dataclasses import dataclass, field
from pathlib import Path

import tree_sitter_javascript as tsjs
from tree_sitter import Language, Parser, Node


@dataclass
class CallInfo:
    """Information about a function call."""
    name: str
    line: int
    column: int
    source: str
    arguments: list[str] = field(default_factory=list)


@dataclass
class TemplateLiteralInfo:
    """Information about a template literal."""
    content: str
    line: int
    column: int
    has_interpolation: bool = False


@dataclass
class AssignmentInfo:
    """Information about an assignment."""
    target: str
    line: int
    column: int
    source: str


@dataclass
class JSParseResult:
    """Result of parsing a JavaScript file."""
    source: str
    has_error: bool = False
    error_message: str = ""
    calls: list[CallInfo] = field(default_factory=list)
    template_literals: list[TemplateLiteralInfo] = field(default_factory=list)
    assignments: list[AssignmentInfo] = field(default_factory=list)
    jsx_elements: list[dict] = field(default_factory=list)


class JavaScriptParser:
    """Parser for JavaScript/TypeScript files using tree-sitter."""

    SUPPORTED_EXTENSIONS = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}

    def __init__(self) -> None:
        self.parser = Parser(Language(tsjs.language()))

    def parse_file(self, file_path: Path) -> JSParseResult:
        """Parse a JavaScript/TypeScript file."""
        try:
            source = file_path.read_text()
            return self.parse_source(source)
        except Exception as e:
            return JSParseResult(
                source="",
                has_error=True,
                error_message=str(e),
            )

    def parse_source(self, source: str) -> JSParseResult:
        """Parse JavaScript source code."""
        try:
            tree = self.parser.parse(source.encode())

            if tree.root_node.has_error:
                return JSParseResult(
                    source=source,
                    has_error=True,
                    error_message="Syntax error in source",
                )

            result = JSParseResult(source=source)
            self._extract_patterns(tree.root_node, source, result)
            return result

        except Exception as e:
            return JSParseResult(
                source=source,
                has_error=True,
                error_message=str(e),
            )

    def _extract_patterns(
        self, node: Node, source: str, result: JSParseResult
    ) -> None:
        """Extract security-relevant patterns from AST."""
        # Process current node
        if node.type == "call_expression":
            self._extract_call(node, source, result)
        elif node.type == "template_string":
            self._extract_template_literal(node, source, result)
        elif node.type == "assignment_expression":
            self._extract_assignment(node, source, result)
        elif node.type == "jsx_element" or node.type == "jsx_self_closing_element":
            self._extract_jsx(node, source, result)

        # Recurse into children
        for child in node.children:
            self._extract_patterns(child, source, result)

    def _extract_call(
        self, node: Node, source: str, result: JSParseResult
    ) -> None:
        """Extract function call information."""
        func_node = node.child_by_field_name("function")
        if not func_node:
            return

        # Get function name
        if func_node.type == "identifier":
            name = source[func_node.start_byte:func_node.end_byte]
        elif func_node.type == "member_expression":
            name = source[func_node.start_byte:func_node.end_byte]
        else:
            name = source[func_node.start_byte:func_node.end_byte]

        call_source = source[node.start_byte:node.end_byte]

        result.calls.append(CallInfo(
            name=name,
            line=node.start_point[0] + 1,
            column=node.start_point[1],
            source=call_source,
        ))

    def _extract_template_literal(
        self, node: Node, source: str, result: JSParseResult
    ) -> None:
        """Extract template literal information."""
        content = source[node.start_byte:node.end_byte]
        has_interpolation = "${" in content

        result.template_literals.append(TemplateLiteralInfo(
            content=content,
            line=node.start_point[0] + 1,
            column=node.start_point[1],
            has_interpolation=has_interpolation,
        ))

    def _extract_assignment(
        self, node: Node, source: str, result: JSParseResult
    ) -> None:
        """Extract assignment information."""
        left = node.child_by_field_name("left")
        if not left:
            return

        target = source[left.start_byte:left.end_byte]
        assign_source = source[node.start_byte:node.end_byte]

        result.assignments.append(AssignmentInfo(
            target=target,
            line=node.start_point[0] + 1,
            column=node.start_point[1],
            source=assign_source,
        ))

    def _extract_jsx(
        self, node: Node, source: str, result: JSParseResult
    ) -> None:
        """Extract JSX element information."""
        jsx_source = source[node.start_byte:node.end_byte]
        result.jsx_elements.append({
            "source": jsx_source,
            "line": node.start_point[0] + 1,
            "column": node.start_point[1],
        })
```

**Step 3: Update __init__.py**

Update `src/hackmenot/parsers/__init__.py`:
```python
"""Parsers module for hackmenot."""

from hackmenot.parsers.javascript import JavaScriptParser
from hackmenot.parsers.python import PythonParser

__all__ = ["PythonParser", "JavaScriptParser"]
```

**Step 4: Run tests**

```bash
pytest tests/test_parsers/test_javascript.py -v
```

**Step 5: Commit**

```bash
git add -A
git commit -m "feat: add JavaScriptParser with tree-sitter"
```

---

## Task 3: Extend Scanner for Multi-language Support

**Files:**
- Modify: `src/hackmenot/core/scanner.py`
- Create: `tests/test_core/test_scanner_js.py`

**Step 1: Write failing tests**

Create `tests/test_core/test_scanner_js.py`:
```python
"""Tests for JavaScript scanning."""

from pathlib import Path

from hackmenot.core.scanner import Scanner


def test_scanner_scans_js_files(tmp_path: Path):
    """Test scanner scans JavaScript files."""
    scanner = Scanner()

    (tmp_path / "test.js").write_text('eval(userInput);')

    result = scanner.scan([tmp_path])

    assert result.files_scanned == 1


def test_scanner_scans_ts_files(tmp_path: Path):
    """Test scanner scans TypeScript files."""
    scanner = Scanner()

    (tmp_path / "test.ts").write_text('const x: number = 1;')

    result = scanner.scan([tmp_path])

    assert result.files_scanned == 1


def test_scanner_scans_mixed_project(tmp_path: Path):
    """Test scanner scans both Python and JavaScript files."""
    scanner = Scanner()

    (tmp_path / "app.py").write_text('x = 1')
    (tmp_path / "app.js").write_text('const x = 1;')

    result = scanner.scan([tmp_path])

    assert result.files_scanned == 2


def test_scanner_detects_js_vulnerabilities(tmp_path: Path):
    """Test scanner detects JavaScript vulnerabilities."""
    scanner = Scanner()

    (tmp_path / "test.js").write_text('eval(userInput);')

    result = scanner.scan([tmp_path])

    # Should find JSIJ001 (eval injection)
    assert any(f.rule_id == "JSIJ001" for f in result.findings)
```

**Step 2: Update scanner.py**

Extend `src/hackmenot/core/scanner.py` to support JavaScript:
- Add JS extensions to SUPPORTED_EXTENSIONS
- Add JavaScriptParser import
- Add language detection method
- Route to correct parser based on extension

**Step 3: Run tests**

```bash
pytest tests/test_core/test_scanner_js.py -v
```

**Step 4: Commit**

```bash
git add -A
git commit -m "feat: extend scanner for JavaScript/TypeScript support"
```

---

## Task 4: Add Injection Rules (JSIJ001-005)

**Files:**
- Create: `src/hackmenot/rules/builtin/injection/JSIJ001.yml` (eval)
- Create: `src/hackmenot/rules/builtin/injection/JSIJ002.yml` (SQL template)
- Create: `src/hackmenot/rules/builtin/injection/JSIJ003.yml` (command injection)
- Create: `src/hackmenot/rules/builtin/injection/JSIJ004.yml` (code injection)
- Create: `src/hackmenot/rules/builtin/injection/JSIJ005.yml` (NoSQL injection)

Each rule follows this format:
```yaml
id: JSIJ001
name: eval-injection
severity: critical
category: injection
languages: [javascript]
description: "Use of eval() with potentially untrusted input"
ai_context: "AI often uses eval() for dynamic code execution which is dangerous"

pattern:
  type: call
  contains: ["eval", "new Function"]

message: "Dangerous use of eval() or Function constructor"

fix:
  template: |
    # Avoid eval(). Use JSON.parse() for JSON, or refactor to avoid dynamic code.

education: |
  eval() executes arbitrary JavaScript code. If user input reaches eval(),
  attackers can execute any code in your application context.

references:
  - https://owasp.org/www-community/attacks/Code_Injection
```

**Step: Create all 5 rules, run tests, commit**

```bash
git add -A
git commit -m "feat: add JavaScript injection rules JSIJ001-005"
```

---

## Task 5: Add Auth Rules (JSAU001-004)

**Files:**
- Create: `src/hackmenot/rules/builtin/auth/JSAU001.yml` (hardcoded secret)
- Create: `src/hackmenot/rules/builtin/auth/JSAU002.yml` (JWT no verify)
- Create: `src/hackmenot/rules/builtin/auth/JSAU003.yml` (insecure cookie)
- Create: `src/hackmenot/rules/builtin/auth/JSAU004.yml` (weak password hash)

**Commit:**

```bash
git add -A
git commit -m "feat: add JavaScript auth rules JSAU001-004"
```

---

## Task 6: Add Crypto Rules (JSCR001-003)

**Files:**
- Create: `src/hackmenot/rules/builtin/crypto/JSCR001.yml` (Math.random)
- Create: `src/hackmenot/rules/builtin/crypto/JSCR002.yml` (weak crypto)
- Create: `src/hackmenot/rules/builtin/crypto/JSCR003.yml` (hardcoded IV)

**Commit:**

```bash
git add -A
git commit -m "feat: add JavaScript crypto rules JSCR001-003"
```

---

## Task 7: Add XSS Rules (XSS001-004) - NEW CATEGORY

**Files:**
- Create: `src/hackmenot/rules/builtin/xss/` directory
- Create: `src/hackmenot/rules/builtin/xss/XSS001.yml` (innerHTML)
- Create: `src/hackmenot/rules/builtin/xss/XSS002.yml` (dangerouslySetInnerHTML)
- Create: `src/hackmenot/rules/builtin/xss/XSS003.yml` (document.write)
- Create: `src/hackmenot/rules/builtin/xss/XSS004.yml` (postMessage)

**Commit:**

```bash
git add -A
git commit -m "feat: add XSS rules XSS001-004"
```

---

## Task 8: Add Validation Rules (JSVA001-004)

**Files:**
- Create: `src/hackmenot/rules/builtin/validation/JSVA001.yml` (prototype pollution)
- Create: `src/hackmenot/rules/builtin/validation/JSVA002.yml` (regex DoS)
- Create: `src/hackmenot/rules/builtin/validation/JSVA003.yml` (path traversal)
- Create: `src/hackmenot/rules/builtin/validation/JSVA004.yml` (open redirect)

**Commit:**

```bash
git add -A
git commit -m "feat: add JavaScript validation rules JSVA001-004"
```

---

## Task 9: Update Rules Engine for JavaScript

**Files:**
- Modify: `src/hackmenot/rules/engine.py`
- Create: `tests/test_rules/test_js_rules.py`

Update rules engine to:
- Handle JSParseResult from JavaScriptParser
- Match patterns against JS-specific AST nodes
- Support `languages: [javascript]` in rules

**Commit:**

```bash
git add -A
git commit -m "feat: update rules engine for JavaScript pattern matching"
```

---

## Task 10: Integration Tests

**Files:**
- Modify: `tests/test_integration.py`

Add tests for:
- JavaScript file scanning end-to-end
- TypeScript file scanning
- JSX/TSX scanning
- Mixed Python + JS projects
- All 20 new rules have detection tests

**Commit:**

```bash
git add -A
git commit -m "feat: add JavaScript integration tests"
```

---

## Summary

**Total Tasks:** 10
**Expected Tests:** ~50 new tests
**Expected Rules:** 20 new JavaScript rules (55 total)

**Key Deliverables:**
1. Tree-sitter based JavaScript/TypeScript parser
2. Multi-language scanner support
3. 20 new security rules for JS/TS
4. New XSS category
5. Full test coverage
