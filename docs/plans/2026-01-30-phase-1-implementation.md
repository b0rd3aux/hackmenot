# Phase 1: Core MVP Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a working `hackmenot scan .` command that scans Python files and reports vulnerabilities with colored terminal output.

**Architecture:** CLI (Typer) → Scanner → Python Parser → Rules Engine → Terminal Reporter. Each component tested independently, composed at the end.

**Tech Stack:** Python 3.11+, Typer, Rich, PyYAML, pytest

---

## Task 1: Project Setup

**Files:**
- Create: `pyproject.toml`
- Create: `src/hackmenot/__init__.py`
- Create: `src/hackmenot/__main__.py`
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`

**Step 1: Create pyproject.toml**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "hackmenot"
version = "0.1.0"
description = "AI-Era Code Security Scanner"
readme = "README.md"
license = "Apache-2.0"
requires-python = ">=3.11"
authors = [
    { name = "hackmenot team" }
]
keywords = ["security", "scanner", "ai", "code-analysis", "sast"]
classifiers = [
    "Development Status :: 3 - Alpha",
    "Environment :: Console",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: Apache Software License",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Security",
    "Topic :: Software Development :: Quality Assurance",
]

dependencies = [
    "typer>=0.9.0",
    "rich>=13.0.0",
    "pyyaml>=6.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
    "pytest-cov>=4.0.0",
    "ruff>=0.1.0",
    "mypy>=1.8.0",
]

[project.scripts]
hackmenot = "hackmenot.cli.main:app"

[project.urls]
Homepage = "https://github.com/hackmenot/hackmenot"
Repository = "https://github.com/hackmenot/hackmenot"

[tool.hatch.build.targets.wheel]
packages = ["src/hackmenot"]

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "I", "N", "W", "UP"]

[tool.mypy]
python_version = "3.11"
strict = true
warn_return_any = true
warn_unused_ignores = true

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-v --tb=short"
```

**Step 2: Create package init**

Create `src/hackmenot/__init__.py`:
```python
"""hackmenot - AI-Era Code Security Scanner."""

__version__ = "0.1.0"
```

**Step 3: Create entry point**

Create `src/hackmenot/__main__.py`:
```python
"""Entry point for python -m hackmenot."""

from hackmenot.cli.main import app

if __name__ == "__main__":
    app()
```

**Step 4: Create test scaffolding**

Create `tests/__init__.py`:
```python
"""hackmenot test suite."""
```

Create `tests/conftest.py`:
```python
"""Pytest configuration and fixtures."""

import pytest
from pathlib import Path

@pytest.fixture
def fixtures_dir() -> Path:
    """Return path to test fixtures directory."""
    return Path(__file__).parent / "fixtures"

@pytest.fixture
def tmp_python_file(tmp_path: Path) -> Path:
    """Create a temporary Python file for testing."""
    file = tmp_path / "test_file.py"
    file.write_text("# empty file\n")
    return file
```

**Step 5: Create fixtures directory**

```bash
mkdir -p tests/fixtures/python
```

**Step 6: Install in dev mode and verify**

```bash
pip install -e ".[dev]"
python -c "import hackmenot; print(hackmenot.__version__)"
```

Expected: `0.1.0`

**Step 7: Commit**

```bash
git add -A
git commit -m "chore: project setup with pyproject.toml and test scaffolding"
```

---

## Task 2: CLI Skeleton

**Files:**
- Create: `src/hackmenot/cli/__init__.py`
- Create: `src/hackmenot/cli/main.py`
- Create: `tests/test_cli/__init__.py`
- Create: `tests/test_cli/test_main.py`

**Step 1: Write the failing test**

Create `tests/test_cli/__init__.py`:
```python
"""CLI tests."""
```

Create `tests/test_cli/test_main.py`:
```python
"""Tests for CLI main entry point."""

from typer.testing import CliRunner
from hackmenot.cli.main import app

runner = CliRunner()


def test_version_flag():
    """Test --version flag shows version."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.stdout


def test_scan_command_exists():
    """Test scan command is available."""
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "Scan" in result.stdout or "scan" in result.stdout.lower()
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_cli/test_main.py -v
```

Expected: FAIL (module not found)

**Step 3: Create CLI package**

Create `src/hackmenot/cli/__init__.py`:
```python
"""CLI module for hackmenot."""

from hackmenot.cli.main import app

__all__ = ["app"]
```

**Step 4: Create main CLI**

Create `src/hackmenot/cli/main.py`:
```python
"""Main CLI entry point using Typer."""

from typing import Optional
from pathlib import Path

import typer
from rich.console import Console

from hackmenot import __version__

app = typer.Typer(
    name="hackmenot",
    help="AI-Era Code Security Scanner",
    add_completion=False,
)
console = Console()


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"hackmenot {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """hackmenot - AI-Era Code Security Scanner."""
    pass


@app.command()
def scan(
    paths: list[Path] = typer.Argument(
        ...,
        help="Paths to scan (files or directories)",
        exists=True,
    ),
    format: str = typer.Option(
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal, json, sarif",
    ),
) -> None:
    """Scan code for security vulnerabilities."""
    console.print(f"[cyan]Scanning {len(paths)} path(s)...[/cyan]")
    # TODO: Implement scanning
    console.print("[green]Scan complete (no rules implemented yet)[/green]")


@app.command()
def rules() -> None:
    """List available security rules."""
    console.print("[yellow]No rules implemented yet[/yellow]")
```

**Step 5: Run tests to verify they pass**

```bash
pytest tests/test_cli/test_main.py -v
```

Expected: 2 passed

**Step 6: Test CLI manually**

```bash
hackmenot --version
hackmenot scan .
hackmenot scan --help
```

**Step 7: Commit**

```bash
git add -A
git commit -m "feat: add CLI skeleton with scan and rules commands"
```

---

## Task 3: Data Models

**Files:**
- Create: `src/hackmenot/core/__init__.py`
- Create: `src/hackmenot/core/models.py`
- Create: `tests/test_core/__init__.py`
- Create: `tests/test_core/test_models.py`

**Step 1: Write the failing test**

Create `tests/test_core/__init__.py`:
```python
"""Core module tests."""
```

Create `tests/test_core/test_models.py`:
```python
"""Tests for core data models."""

import pytest
from hackmenot.core.models import Severity, Finding, Rule, ScanResult


def test_severity_ordering():
    """Test severity levels are ordered correctly."""
    assert Severity.CRITICAL > Severity.HIGH
    assert Severity.HIGH > Severity.MEDIUM
    assert Severity.MEDIUM > Severity.LOW


def test_finding_creation():
    """Test Finding dataclass creation."""
    finding = Finding(
        rule_id="AUTH001",
        rule_name="missing-auth",
        severity=Severity.HIGH,
        message="Missing authentication",
        file_path="src/api.py",
        line_number=42,
        column=0,
        code_snippet="def get_user():",
        fix_suggestion="Add @login_required decorator",
        education="AI often skips auth checks",
    )
    assert finding.rule_id == "AUTH001"
    assert finding.severity == Severity.HIGH
    assert finding.line_number == 42


def test_rule_creation():
    """Test Rule dataclass creation."""
    rule = Rule(
        id="AUTH001",
        name="missing-auth",
        severity=Severity.HIGH,
        category="authentication",
        languages=["python"],
        description="Missing authentication decorator",
        message="Endpoint missing auth",
        pattern={"type": "ast"},
        fix_template="@login_required\n{original}",
        education="AI skips auth",
    )
    assert rule.id == "AUTH001"
    assert "python" in rule.languages


def test_scan_result_summary():
    """Test ScanResult computes summary correctly."""
    findings = [
        Finding(
            rule_id="A", rule_name="a", severity=Severity.CRITICAL,
            message="m", file_path="f", line_number=1, column=0,
            code_snippet="c", fix_suggestion="", education="",
        ),
        Finding(
            rule_id="B", rule_name="b", severity=Severity.HIGH,
            message="m", file_path="f", line_number=2, column=0,
            code_snippet="c", fix_suggestion="", education="",
        ),
        Finding(
            rule_id="C", rule_name="c", severity=Severity.HIGH,
            message="m", file_path="f", line_number=3, column=0,
            code_snippet="c", fix_suggestion="", education="",
        ),
    ]
    result = ScanResult(files_scanned=10, findings=findings, scan_time_ms=100)

    summary = result.summary_by_severity()
    assert summary[Severity.CRITICAL] == 1
    assert summary[Severity.HIGH] == 2
    assert summary[Severity.MEDIUM] == 0
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_core/test_models.py -v
```

Expected: FAIL (module not found)

**Step 3: Create models**

Create `src/hackmenot/core/__init__.py`:
```python
"""Core module for hackmenot."""

from hackmenot.core.models import Severity, Finding, Rule, ScanResult

__all__ = ["Severity", "Finding", "Rule", "ScanResult"]
```

Create `src/hackmenot/core/models.py`:
```python
"""Core data models for hackmenot."""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Severity levels for findings, ordered for comparison."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name.lower()

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Create Severity from string (case-insensitive)."""
        return cls[value.upper()]


@dataclass(frozen=True)
class Finding:
    """A security finding in scanned code."""

    rule_id: str
    rule_name: str
    severity: Severity
    message: str
    file_path: str
    line_number: int
    column: int
    code_snippet: str
    fix_suggestion: str
    education: str
    context_before: list[str] = field(default_factory=list)
    context_after: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Rule:
    """A security rule definition."""

    id: str
    name: str
    severity: Severity
    category: str
    languages: list[str]
    description: str
    message: str
    pattern: dict[str, Any]
    fix_template: str = ""
    education: str = ""
    references: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Result of a scan operation."""

    files_scanned: int
    findings: list[Finding]
    scan_time_ms: float
    errors: list[str] = field(default_factory=list)

    def summary_by_severity(self) -> dict[Severity, int]:
        """Count findings by severity level."""
        counts = {s: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    @property
    def has_findings(self) -> bool:
        """Check if there are any findings."""
        return len(self.findings) > 0

    def findings_at_or_above(self, min_severity: Severity) -> list[Finding]:
        """Get findings at or above a minimum severity."""
        return [f for f in self.findings if f.severity >= min_severity]
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/test_core/test_models.py -v
```

Expected: 4 passed

**Step 5: Commit**

```bash
git add -A
git commit -m "feat: add core data models (Severity, Finding, Rule, ScanResult)"
```

---

## Task 4: Python AST Parser

**Files:**
- Create: `src/hackmenot/parsers/__init__.py`
- Create: `src/hackmenot/parsers/base.py`
- Create: `src/hackmenot/parsers/python.py`
- Create: `tests/test_parsers/__init__.py`
- Create: `tests/test_parsers/test_python.py`
- Create: `tests/fixtures/python/simple_function.py`

**Step 1: Create test fixtures**

Create `tests/fixtures/python/simple_function.py`:
```python
def hello(name):
    return f"Hello, {name}!"


@app.route("/users")
def get_users():
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return execute(query)


class UserService:
    def __init__(self, db):
        self.db = db

    def find_user(self, user_id):
        return self.db.query(f"SELECT * FROM users WHERE id = {user_id}")
```

**Step 2: Write the failing test**

Create `tests/test_parsers/__init__.py`:
```python
"""Parser tests."""
```

Create `tests/test_parsers/test_python.py`:
```python
"""Tests for Python AST parser."""

import pytest
from pathlib import Path
from hackmenot.parsers.python import PythonParser


@pytest.fixture
def parser():
    return PythonParser()


@pytest.fixture
def simple_function_file(fixtures_dir: Path) -> Path:
    return fixtures_dir / "python" / "simple_function.py"


def test_parser_can_parse_file(parser, simple_function_file):
    """Test parser can parse a Python file."""
    result = parser.parse_file(simple_function_file)
    assert result is not None
    assert result.file_path == simple_function_file


def test_parser_extracts_functions(parser, simple_function_file):
    """Test parser extracts function definitions."""
    result = parser.parse_file(simple_function_file)
    functions = result.get_functions()

    assert len(functions) >= 2
    func_names = [f.name for f in functions]
    assert "hello" in func_names
    assert "get_users" in func_names


def test_parser_extracts_function_decorators(parser, simple_function_file):
    """Test parser extracts decorators from functions."""
    result = parser.parse_file(simple_function_file)
    functions = result.get_functions()

    get_users = next(f for f in functions if f.name == "get_users")
    assert len(get_users.decorators) > 0
    assert any("route" in d for d in get_users.decorators)


def test_parser_extracts_fstrings(parser, simple_function_file):
    """Test parser extracts f-string expressions."""
    result = parser.parse_file(simple_function_file)
    fstrings = result.get_fstrings()

    assert len(fstrings) >= 2
    # Should find SQL-like f-strings
    sql_fstrings = [f for f in fstrings if "SELECT" in f.value]
    assert len(sql_fstrings) >= 1


def test_parser_extracts_classes(parser, simple_function_file):
    """Test parser extracts class definitions."""
    result = parser.parse_file(simple_function_file)
    classes = result.get_classes()

    assert len(classes) >= 1
    assert any(c.name == "UserService" for c in classes)


def test_parser_handles_syntax_error(parser, tmp_path):
    """Test parser handles invalid Python gracefully."""
    bad_file = tmp_path / "bad.py"
    bad_file.write_text("def broken(\n")

    result = parser.parse_file(bad_file)
    assert result.has_error
    assert result.error_message is not None
```

**Step 3: Run test to verify it fails**

```bash
pytest tests/test_parsers/test_python.py -v
```

Expected: FAIL (module not found)

**Step 4: Create parser base class**

Create `src/hackmenot/parsers/__init__.py`:
```python
"""Parsers module for hackmenot."""

from hackmenot.parsers.python import PythonParser

__all__ = ["PythonParser"]
```

Create `src/hackmenot/parsers/base.py`:
```python
"""Base parser interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class FunctionInfo:
    """Information about a function definition."""

    name: str
    line_number: int
    column: int
    decorators: list[str] = field(default_factory=list)
    args: list[str] = field(default_factory=list)
    body_start: int = 0
    body_end: int = 0


@dataclass
class ClassInfo:
    """Information about a class definition."""

    name: str
    line_number: int
    column: int
    bases: list[str] = field(default_factory=list)
    methods: list[FunctionInfo] = field(default_factory=list)


@dataclass
class FStringInfo:
    """Information about an f-string."""

    value: str
    line_number: int
    column: int
    variables: list[str] = field(default_factory=list)


@dataclass
class ParseResult:
    """Result of parsing a file."""

    file_path: Path
    has_error: bool = False
    error_message: str | None = None
    _functions: list[FunctionInfo] = field(default_factory=list)
    _classes: list[ClassInfo] = field(default_factory=list)
    _fstrings: list[FStringInfo] = field(default_factory=list)
    _raw_ast: Any = None

    def get_functions(self) -> list[FunctionInfo]:
        """Get all function definitions."""
        return self._functions

    def get_classes(self) -> list[ClassInfo]:
        """Get all class definitions."""
        return self._classes

    def get_fstrings(self) -> list[FStringInfo]:
        """Get all f-strings."""
        return self._fstrings


class BaseParser(ABC):
    """Abstract base class for language parsers."""

    @abstractmethod
    def parse_file(self, file_path: Path) -> ParseResult:
        """Parse a file and return structured result."""
        pass

    @abstractmethod
    def parse_string(self, source: str, filename: str = "<string>") -> ParseResult:
        """Parse source code string and return structured result."""
        pass
```

**Step 5: Create Python parser**

Create `src/hackmenot/parsers/python.py`:
```python
"""Python AST parser."""

import ast
from pathlib import Path
from typing import Any

from hackmenot.parsers.base import (
    BaseParser,
    ClassInfo,
    FStringInfo,
    FunctionInfo,
    ParseResult,
)


class PythonParser(BaseParser):
    """Parser for Python source files using the ast module."""

    def parse_file(self, file_path: Path) -> ParseResult:
        """Parse a Python file."""
        try:
            source = file_path.read_text(encoding="utf-8")
            return self.parse_string(source, str(file_path))
        except Exception as e:
            return ParseResult(
                file_path=file_path,
                has_error=True,
                error_message=str(e),
            )

    def parse_string(self, source: str, filename: str = "<string>") -> ParseResult:
        """Parse Python source code string."""
        file_path = Path(filename)

        try:
            tree = ast.parse(source, filename=filename)
        except SyntaxError as e:
            return ParseResult(
                file_path=file_path,
                has_error=True,
                error_message=f"Syntax error: {e}",
            )

        visitor = _PythonASTVisitor()
        visitor.visit(tree)

        return ParseResult(
            file_path=file_path,
            _functions=visitor.functions,
            _classes=visitor.classes,
            _fstrings=visitor.fstrings,
            _raw_ast=tree,
        )


class _PythonASTVisitor(ast.NodeVisitor):
    """AST visitor that extracts relevant information."""

    def __init__(self) -> None:
        self.functions: list[FunctionInfo] = []
        self.classes: list[ClassInfo] = []
        self.fstrings: list[FStringInfo] = []
        self._current_class: ClassInfo | None = None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definition."""
        func_info = self._extract_function_info(node)

        if self._current_class is not None:
            self._current_class.methods.append(func_info)
        else:
            self.functions.append(func_info)

        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit async function definition."""
        func_info = self._extract_function_info(node)

        if self._current_class is not None:
            self._current_class.methods.append(func_info)
        else:
            self.functions.append(func_info)

        self.generic_visit(node)

    def _extract_function_info(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> FunctionInfo:
        """Extract function information from AST node."""
        decorators = []
        for dec in node.decorator_list:
            decorators.append(ast.unparse(dec))

        args = []
        for arg in node.args.args:
            args.append(arg.arg)

        body_end = node.end_lineno if node.end_lineno else node.lineno

        return FunctionInfo(
            name=node.name,
            line_number=node.lineno,
            column=node.col_offset,
            decorators=decorators,
            args=args,
            body_start=node.lineno,
            body_end=body_end,
        )

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit class definition."""
        bases = [ast.unparse(base) for base in node.bases]

        class_info = ClassInfo(
            name=node.name,
            line_number=node.lineno,
            column=node.col_offset,
            bases=bases,
        )

        # Set current class context for methods
        old_class = self._current_class
        self._current_class = class_info

        self.generic_visit(node)

        self._current_class = old_class
        self.classes.append(class_info)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        """Visit f-string (JoinedStr in AST)."""
        # Reconstruct the f-string value
        parts = []
        variables = []

        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
            elif isinstance(value, ast.FormattedValue):
                var_repr = ast.unparse(value.value)
                parts.append(f"{{{var_repr}}}")
                variables.append(var_repr)

        fstring_info = FStringInfo(
            value="".join(parts),
            line_number=node.lineno,
            column=node.col_offset,
            variables=variables,
        )
        self.fstrings.append(fstring_info)

        self.generic_visit(node)
```

**Step 6: Run tests to verify they pass**

```bash
pytest tests/test_parsers/test_python.py -v
```

Expected: 6 passed

**Step 7: Commit**

```bash
git add -A
git commit -m "feat: add Python AST parser with function, class, and fstring extraction"
```

---

## Task 5: Rules Engine

**Files:**
- Create: `src/hackmenot/rules/__init__.py`
- Create: `src/hackmenot/rules/engine.py`
- Create: `src/hackmenot/rules/registry.py`
- Create: `tests/test_rules/__init__.py`
- Create: `tests/test_rules/test_engine.py`

**Step 1: Write the failing test**

Create `tests/test_rules/__init__.py`:
```python
"""Rules tests."""
```

Create `tests/test_rules/test_engine.py`:
```python
"""Tests for rules engine."""

import pytest
from pathlib import Path
from hackmenot.core.models import Severity, Rule
from hackmenot.rules.engine import RulesEngine
from hackmenot.parsers.python import PythonParser


@pytest.fixture
def engine():
    return RulesEngine()


@pytest.fixture
def parser():
    return PythonParser()


@pytest.fixture
def sql_injection_rule():
    return Rule(
        id="INJ001",
        name="sql-injection-fstring",
        severity=Severity.CRITICAL,
        category="injection",
        languages=["python"],
        description="Possible SQL injection via f-string",
        message="SQL query built with f-string may be vulnerable to injection",
        pattern={
            "type": "fstring",
            "contains": ["SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE"],
        },
        fix_template="Use parameterized queries instead",
        education="AI often generates SQL queries using f-strings for simplicity, but this is vulnerable to SQL injection.",
    )


def test_engine_can_register_rule(engine, sql_injection_rule):
    """Test engine can register a rule."""
    engine.register_rule(sql_injection_rule)
    assert sql_injection_rule.id in engine.rules


def test_engine_can_check_file(engine, sql_injection_rule, parser, fixtures_dir):
    """Test engine can check a file against rules."""
    engine.register_rule(sql_injection_rule)

    file_path = fixtures_dir / "python" / "simple_function.py"
    parse_result = parser.parse_file(file_path)

    findings = engine.check(parse_result, file_path)

    # Should find SQL injection in f-strings
    assert len(findings) >= 1
    assert findings[0].rule_id == "INJ001"


def test_engine_returns_empty_for_clean_code(engine, sql_injection_rule, parser, tmp_path):
    """Test engine returns no findings for clean code."""
    engine.register_rule(sql_injection_rule)

    clean_file = tmp_path / "clean.py"
    clean_file.write_text('def hello():\n    return "Hello, World!"\n')

    parse_result = parser.parse_file(clean_file)
    findings = engine.check(parse_result, clean_file)

    assert len(findings) == 0


def test_engine_skips_rules_for_other_languages(engine, parser, tmp_path):
    """Test engine skips rules not matching file language."""
    js_only_rule = Rule(
        id="JS001",
        name="js-only",
        severity=Severity.LOW,
        category="test",
        languages=["javascript"],
        description="JS only rule",
        message="This should not match Python",
        pattern={"type": "fstring", "contains": ["test"]},
    )
    engine.register_rule(js_only_rule)

    py_file = tmp_path / "test.py"
    py_file.write_text('x = f"test string"\n')

    parse_result = parser.parse_file(py_file)
    findings = engine.check(parse_result, py_file)

    assert len(findings) == 0
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_rules/test_engine.py -v
```

Expected: FAIL (module not found)

**Step 3: Create rules engine**

Create `src/hackmenot/rules/__init__.py`:
```python
"""Rules module for hackmenot."""

from hackmenot.rules.engine import RulesEngine
from hackmenot.rules.registry import RuleRegistry

__all__ = ["RulesEngine", "RuleRegistry"]
```

Create `src/hackmenot/rules/engine.py`:
```python
"""Rules engine for matching patterns against parsed code."""

from pathlib import Path

from hackmenot.core.models import Finding, Rule, Severity
from hackmenot.parsers.base import ParseResult


class RulesEngine:
    """Engine for checking code against security rules."""

    def __init__(self) -> None:
        self.rules: dict[str, Rule] = {}

    def register_rule(self, rule: Rule) -> None:
        """Register a rule with the engine."""
        self.rules[rule.id] = rule

    def check(self, parse_result: ParseResult, file_path: Path) -> list[Finding]:
        """Check parsed code against all registered rules."""
        if parse_result.has_error:
            return []

        findings: list[Finding] = []
        language = self._detect_language(file_path)

        for rule in self.rules.values():
            if language not in rule.languages:
                continue

            rule_findings = self._check_rule(rule, parse_result, file_path)
            findings.extend(rule_findings)

        return findings

    def _detect_language(self, file_path: Path) -> str:
        """Detect language from file extension."""
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
        }
        return ext_map.get(file_path.suffix.lower(), "unknown")

    def _check_rule(
        self, rule: Rule, parse_result: ParseResult, file_path: Path
    ) -> list[Finding]:
        """Check a single rule against parsed code."""
        findings: list[Finding] = []
        pattern = rule.pattern
        pattern_type = pattern.get("type", "")

        if pattern_type == "fstring":
            findings.extend(
                self._check_fstring_pattern(rule, parse_result, file_path)
            )
        elif pattern_type == "function":
            findings.extend(
                self._check_function_pattern(rule, parse_result, file_path)
            )

        return findings

    def _check_fstring_pattern(
        self, rule: Rule, parse_result: ParseResult, file_path: Path
    ) -> list[Finding]:
        """Check f-string patterns."""
        findings: list[Finding] = []
        contains = rule.pattern.get("contains", [])

        for fstring in parse_result.get_fstrings():
            # Check if f-string contains any of the target strings
            if any(kw.upper() in fstring.value.upper() for kw in contains):
                # Only flag if there are interpolated variables
                if fstring.variables:
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            message=rule.message,
                            file_path=str(file_path),
                            line_number=fstring.line_number,
                            column=fstring.column,
                            code_snippet=f'f"{fstring.value}"',
                            fix_suggestion=rule.fix_template,
                            education=rule.education,
                        )
                    )

        return findings

    def _check_function_pattern(
        self, rule: Rule, parse_result: ParseResult, file_path: Path
    ) -> list[Finding]:
        """Check function patterns (decorators, etc.)."""
        findings: list[Finding] = []

        has_decorator = rule.pattern.get("has_decorator", [])
        missing_decorator = rule.pattern.get("missing_decorator", [])

        for func in parse_result.get_functions():
            # Check if function has required decorator
            has_target = any(
                any(d in dec for d in has_decorator)
                for dec in func.decorators
            )

            if has_target:
                # Check if missing security decorator
                has_security = any(
                    any(s in dec for s in missing_decorator)
                    for dec in func.decorators
                )

                if not has_security:
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            message=rule.message.format(function_name=func.name),
                            file_path=str(file_path),
                            line_number=func.line_number,
                            column=func.column,
                            code_snippet=f"def {func.name}(...):",
                            fix_suggestion=rule.fix_template,
                            education=rule.education,
                        )
                    )

        return findings
```

Create `src/hackmenot/rules/registry.py`:
```python
"""Rule registry for loading and managing rules."""

from pathlib import Path
from typing import Iterator

import yaml

from hackmenot.core.models import Rule, Severity


class RuleRegistry:
    """Registry for loading rules from YAML files."""

    def __init__(self, rules_dir: Path | None = None) -> None:
        self.rules_dir = rules_dir or self._default_rules_dir()
        self._rules: dict[str, Rule] = {}

    def _default_rules_dir(self) -> Path:
        """Get default rules directory."""
        return Path(__file__).parent / "builtin"

    def load_all(self) -> None:
        """Load all rules from the rules directory."""
        if not self.rules_dir.exists():
            return

        for rule_file in self.rules_dir.rglob("*.yml"):
            self._load_rule_file(rule_file)

        for rule_file in self.rules_dir.rglob("*.yaml"):
            self._load_rule_file(rule_file)

    def _load_rule_file(self, file_path: Path) -> None:
        """Load a single rule file."""
        try:
            with open(file_path) as f:
                data = yaml.safe_load(f)

            if data:
                rule = self._parse_rule(data)
                self._rules[rule.id] = rule
        except Exception as e:
            # Log error but continue loading other rules
            print(f"Warning: Failed to load rule {file_path}: {e}")

    def _parse_rule(self, data: dict) -> Rule:
        """Parse rule data into Rule object."""
        return Rule(
            id=data["id"],
            name=data["name"],
            severity=Severity.from_string(data["severity"]),
            category=data["category"],
            languages=data.get("languages", ["python"]),
            description=data.get("description", ""),
            message=data["message"],
            pattern=data.get("pattern", {}),
            fix_template=data.get("fix", {}).get("template", ""),
            education=data.get("education", ""),
            references=data.get("references", []),
        )

    def get_rule(self, rule_id: str) -> Rule | None:
        """Get a rule by ID."""
        return self._rules.get(rule_id)

    def get_all_rules(self) -> Iterator[Rule]:
        """Iterate over all loaded rules."""
        yield from self._rules.values()

    def get_rules_by_category(self, category: str) -> Iterator[Rule]:
        """Get all rules in a category."""
        for rule in self._rules.values():
            if rule.category == category:
                yield rule
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/test_rules/test_engine.py -v
```

Expected: 4 passed

**Step 5: Commit**

```bash
git add -A
git commit -m "feat: add rules engine with pattern matching for fstrings and functions"
```

---

## Task 6: Built-in Rules (10 initial rules)

**Files:**
- Create: `src/hackmenot/rules/builtin/injection/INJ001.yml`
- Create: `src/hackmenot/rules/builtin/injection/INJ002.yml`
- Create: `src/hackmenot/rules/builtin/auth/AUTH001.yml`
- Create: `src/hackmenot/rules/builtin/auth/AUTH002.yml`
- Create: `src/hackmenot/rules/builtin/crypto/CRYPTO001.yml`
- Create: `src/hackmenot/rules/builtin/crypto/CRYPTO002.yml`
- Create: `src/hackmenot/rules/builtin/exposure/EXP001.yml`
- Create: `src/hackmenot/rules/builtin/exposure/EXP002.yml`
- Create: `src/hackmenot/rules/builtin/deps/DEP001.yml`
- Create: `src/hackmenot/rules/builtin/deps/DEP002.yml`
- Create: `tests/test_rules/test_builtin.py`

**Step 1: Create directory structure**

```bash
mkdir -p src/hackmenot/rules/builtin/{injection,auth,crypto,exposure,deps}
```

**Step 2: Create injection rules**

Create `src/hackmenot/rules/builtin/injection/INJ001.yml`:
```yaml
id: INJ001
name: sql-injection-fstring
severity: critical
category: injection
languages: [python]
description: "SQL query built using f-string with user input"
ai_context: "AI assistants often use f-strings for SQL queries because they're concise, but this creates SQL injection vulnerabilities"

pattern:
  type: fstring
  contains: ["SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE"]

message: "Possible SQL injection: query built with f-string interpolation"

fix:
  template: |
    # Use parameterized queries instead:
    # cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

education: |
  AI coding assistants often generate SQL queries using f-strings for simplicity.
  This is vulnerable to SQL injection attacks. Always use parameterized queries
  or an ORM that handles escaping automatically.

references:
  - https://owasp.org/www-community/attacks/SQL_Injection
```

Create `src/hackmenot/rules/builtin/injection/INJ002.yml`:
```yaml
id: INJ002
name: command-injection-fstring
severity: critical
category: injection
languages: [python]
description: "Shell command built using f-string with user input"
ai_context: "AI often generates shell commands with f-strings, creating command injection risks"

pattern:
  type: fstring
  contains: ["os.system", "subprocess", "shell=True", "exec(", "eval("]

message: "Possible command injection: shell command built with f-string"

fix:
  template: |
    # Use subprocess with list arguments instead:
    # subprocess.run(["command", arg1, arg2], shell=False)

education: |
  Building shell commands with f-strings allows attackers to inject malicious commands.
  Use subprocess.run() with a list of arguments and shell=False.

references:
  - https://owasp.org/www-community/attacks/Command_Injection
```

**Step 3: Create auth rules**

Create `src/hackmenot/rules/builtin/auth/AUTH001.yml`:
```yaml
id: AUTH001
name: missing-auth-decorator
severity: high
category: authentication
languages: [python]
description: "Route handler missing authentication decorator"
ai_context: "AI often generates Flask/FastAPI routes without authentication, assuming the happy path"

pattern:
  type: function
  has_decorator: ["app.route", "app.get", "app.post", "app.put", "app.delete", "router.get", "router.post"]
  missing_decorator: ["login_required", "auth_required", "jwt_required", "Depends(get_current_user)", "requires_auth"]

message: "Endpoint '{function_name}' has no authentication decorator"

fix:
  template: |
    @login_required  # Add appropriate auth decorator
    {original}

education: |
  AI coding tools frequently generate API endpoints without authentication.
  Always explicitly add authentication decorators or middleware.
  Prompt AI with: "Add authentication using [your auth pattern]"

references:
  - https://owasp.org/API-Security/
```

Create `src/hackmenot/rules/builtin/auth/AUTH002.yml`:
```yaml
id: AUTH002
name: hardcoded-secret
severity: critical
category: authentication
languages: [python]
description: "Hardcoded secret or API key in source code"
ai_context: "AI often includes placeholder secrets that developers forget to replace"

pattern:
  type: fstring
  contains: ["SECRET_KEY", "API_KEY", "PASSWORD", "TOKEN", "PRIVATE_KEY"]

message: "Possible hardcoded secret in source code"

fix:
  template: |
    # Load secrets from environment variables:
    # import os
    # SECRET_KEY = os.environ.get("SECRET_KEY")

education: |
  AI assistants often generate placeholder secrets like "your-secret-key-here".
  These frequently get committed to version control. Always load secrets from
  environment variables or a secrets manager.

references:
  - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information
```

**Step 4: Create crypto rules**

Create `src/hackmenot/rules/builtin/crypto/CRYPTO001.yml`:
```yaml
id: CRYPTO001
name: weak-hash-md5
severity: high
category: cryptography
languages: [python]
description: "Use of MD5 hash algorithm"
ai_context: "AI training data contains many examples using MD5, though it's cryptographically broken"

pattern:
  type: fstring
  contains: ["md5(", "hashlib.md5"]

message: "MD5 is cryptographically broken and should not be used for security"

fix:
  template: |
    # Use SHA-256 or better:
    # import hashlib
    # hashlib.sha256(data).hexdigest()

education: |
  MD5 has known collision vulnerabilities and should not be used for security purposes.
  AI often suggests MD5 because it appears frequently in training data.
  Use SHA-256 or SHA-3 for cryptographic hashing, or bcrypt/argon2 for passwords.

references:
  - https://www.kb.cert.org/vuls/id/836068
```

Create `src/hackmenot/rules/builtin/crypto/CRYPTO002.yml`:
```yaml
id: CRYPTO002
name: weak-hash-sha1
severity: medium
category: cryptography
languages: [python]
description: "Use of SHA1 hash algorithm"
ai_context: "SHA1 is deprecated for security use but AI still commonly suggests it"

pattern:
  type: fstring
  contains: ["sha1(", "hashlib.sha1"]

message: "SHA1 is deprecated for security purposes"

fix:
  template: |
    # Use SHA-256 or better:
    # import hashlib
    # hashlib.sha256(data).hexdigest()

education: |
  SHA1 has theoretical collision attacks and is deprecated for security use.
  Use SHA-256 or SHA-3 for cryptographic hashing.

references:
  - https://shattered.io/
```

**Step 5: Create exposure rules**

Create `src/hackmenot/rules/builtin/exposure/EXP001.yml`:
```yaml
id: EXP001
name: debug-mode-enabled
severity: high
category: exposure
languages: [python]
description: "Debug mode enabled in production code"
ai_context: "AI examples often include debug=True for convenience during development"

pattern:
  type: fstring
  contains: ["debug=True", "DEBUG=True", "DEBUG = True"]

message: "Debug mode appears to be enabled - ensure this is disabled in production"

fix:
  template: |
    # Use environment variable:
    # DEBUG = os.environ.get("DEBUG", "false").lower() == "true"

education: |
  AI-generated code often includes debug=True for convenience.
  Debug mode can expose sensitive information and should never be enabled in production.
  Use environment variables to control debug settings.

references:
  - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/
```

Create `src/hackmenot/rules/builtin/exposure/EXP002.yml`:
```yaml
id: EXP002
name: verbose-error-messages
severity: medium
category: exposure
languages: [python]
description: "Verbose error messages may expose sensitive information"
ai_context: "AI often generates detailed error messages for debugging that leak internals"

pattern:
  type: fstring
  contains: ["traceback", "exc_info", "print(e)", "print(error)", "str(exception)"]

message: "Verbose error handling may expose sensitive information"

fix:
  template: |
    # Log errors securely, return generic message to users:
    # logger.exception("Internal error")
    # return {"error": "An internal error occurred"}

education: |
  AI assistants often generate detailed error messages that include stack traces,
  database queries, or internal paths. These should be logged securely but not
  returned to users.

references:
  - https://owasp.org/www-community/Improper_Error_Handling
```

**Step 6: Create dependency rules**

Create `src/hackmenot/rules/builtin/deps/DEP001.yml`:
```yaml
id: DEP001
name: hallucinated-import
severity: critical
category: dependencies
languages: [python]
description: "Import of potentially non-existent package"
ai_context: "AI sometimes invents plausible-sounding package names that don't exist"

pattern:
  type: import
  check: package_exists

message: "Package '{package_name}' may not exist - verify on PyPI"

fix:
  template: |
    # Verify the package exists on PyPI before using:
    # pip search {package_name}
    # Or check: https://pypi.org/project/{package_name}/

education: |
  AI assistants sometimes "hallucinate" package names that sound plausible but don't exist.
  Attackers can register these names with malicious code. Always verify packages exist
  on PyPI/npm before adding them to your project.

references:
  - https://blog.phylum.io/phylum-discovers-npm-package-mathjs-min-contains-discord-token-grabber
```

Create `src/hackmenot/rules/builtin/deps/DEP002.yml`:
```yaml
id: DEP002
name: typosquat-risk
severity: high
category: dependencies
languages: [python]
description: "Import similar to popular package - possible typosquat"
ai_context: "AI may generate slightly misspelled package names"

pattern:
  type: import
  check: typosquat

message: "Package '{package_name}' is similar to '{similar_to}' - possible typosquat"

fix:
  template: |
    # Verify you're using the correct package name.
    # Did you mean: {similar_to}?

education: |
  Typosquatting is when attackers register package names similar to popular packages.
  AI may accidentally generate these misspellings. Always double-check package names,
  especially for popular packages like 'requests', 'django', 'flask'.

references:
  - https://snyk.io/blog/typosquatting-attacks/
```

**Step 7: Write test for builtin rules**

Create `tests/test_rules/test_builtin.py`:
```python
"""Tests for built-in rules."""

import pytest
from pathlib import Path
from hackmenot.rules.registry import RuleRegistry
from hackmenot.rules.engine import RulesEngine
from hackmenot.parsers.python import PythonParser


@pytest.fixture
def registry():
    reg = RuleRegistry()
    reg.load_all()
    return reg


@pytest.fixture
def engine(registry):
    eng = RulesEngine()
    for rule in registry.get_all_rules():
        eng.register_rule(rule)
    return eng


@pytest.fixture
def parser():
    return PythonParser()


def test_registry_loads_builtin_rules(registry):
    """Test registry loads all built-in rules."""
    rules = list(registry.get_all_rules())
    assert len(rules) >= 10


def test_inj001_detects_sql_fstring(engine, parser, tmp_path):
    """Test INJ001 detects SQL injection via f-string."""
    code = '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
'''
    file = tmp_path / "test.py"
    file.write_text(code)

    result = parser.parse_file(file)
    findings = engine.check(result, file)

    inj_findings = [f for f in findings if f.rule_id == "INJ001"]
    assert len(inj_findings) >= 1


def test_auth001_detects_missing_auth(engine, parser, tmp_path):
    """Test AUTH001 detects missing auth decorator."""
    code = '''
from flask import Flask
app = Flask(__name__)

@app.route("/users")
def get_users():
    return users
'''
    file = tmp_path / "test.py"
    file.write_text(code)

    result = parser.parse_file(file)
    findings = engine.check(result, file)

    auth_findings = [f for f in findings if f.rule_id == "AUTH001"]
    assert len(auth_findings) >= 1


def test_clean_code_has_no_findings(engine, parser, tmp_path):
    """Test clean code produces no findings."""
    code = '''
def hello(name: str) -> str:
    """Say hello to someone."""
    return f"Hello, {name}!"
'''
    file = tmp_path / "clean.py"
    file.write_text(code)

    result = parser.parse_file(file)
    findings = engine.check(result, file)

    # Should have no critical/high findings for this simple code
    critical_high = [f for f in findings if f.severity.value >= 3]
    assert len(critical_high) == 0
```

**Step 8: Run tests**

```bash
pytest tests/test_rules/test_builtin.py -v
```

Expected: 4 passed

**Step 9: Commit**

```bash
git add -A
git commit -m "feat: add 10 built-in security rules (injection, auth, crypto, exposure, deps)"
```

---

## Task 7: Terminal Reporter with Colors

**Files:**
- Create: `src/hackmenot/reporters/__init__.py`
- Create: `src/hackmenot/reporters/base.py`
- Create: `src/hackmenot/reporters/terminal.py`
- Create: `tests/test_reporters/__init__.py`
- Create: `tests/test_reporters/test_terminal.py`

**Step 1: Write the failing test**

Create `tests/test_reporters/__init__.py`:
```python
"""Reporter tests."""
```

Create `tests/test_reporters/test_terminal.py`:
```python
"""Tests for terminal reporter."""

import pytest
from io import StringIO
from rich.console import Console
from hackmenot.core.models import Severity, Finding, ScanResult
from hackmenot.reporters.terminal import TerminalReporter


@pytest.fixture
def reporter():
    return TerminalReporter()


@pytest.fixture
def sample_findings():
    return [
        Finding(
            rule_id="INJ001",
            rule_name="sql-injection",
            severity=Severity.CRITICAL,
            message="SQL injection detected",
            file_path="src/api.py",
            line_number=42,
            column=0,
            code_snippet='f"SELECT * FROM users WHERE id = {user_id}"',
            fix_suggestion="Use parameterized queries",
            education="AI often generates vulnerable SQL",
        ),
        Finding(
            rule_id="AUTH001",
            rule_name="missing-auth",
            severity=Severity.HIGH,
            message="Missing authentication",
            file_path="src/api.py",
            line_number=50,
            column=0,
            code_snippet="def get_users():",
            fix_suggestion="Add @login_required",
            education="AI skips auth decorators",
        ),
    ]


@pytest.fixture
def sample_result(sample_findings):
    return ScanResult(
        files_scanned=10,
        findings=sample_findings,
        scan_time_ms=150,
    )


def test_reporter_renders_header(reporter, sample_result):
    """Test reporter renders header."""
    output = StringIO()
    console = Console(file=output, force_terminal=True, width=80)
    reporter.console = console

    reporter.render(sample_result)
    result = output.getvalue()

    assert "hackmenot" in result.lower()


def test_reporter_renders_findings(reporter, sample_result):
    """Test reporter renders all findings."""
    output = StringIO()
    console = Console(file=output, force_terminal=True, width=80)
    reporter.console = console

    reporter.render(sample_result)
    result = output.getvalue()

    assert "INJ001" in result
    assert "AUTH001" in result
    assert "src/api.py" in result


def test_reporter_renders_summary(reporter, sample_result):
    """Test reporter renders summary with counts."""
    output = StringIO()
    console = Console(file=output, force_terminal=True, width=80)
    reporter.console = console

    reporter.render(sample_result)
    result = output.getvalue()

    assert "10" in result  # files scanned
    assert "Critical" in result or "critical" in result.lower()


def test_reporter_handles_no_findings(reporter):
    """Test reporter handles empty results."""
    result = ScanResult(files_scanned=5, findings=[], scan_time_ms=50)

    output = StringIO()
    console = Console(file=output, force_terminal=True, width=80)
    reporter.console = console

    reporter.render(result)
    rendered = output.getvalue()

    assert "No issues found" in rendered or "0" in rendered
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_reporters/test_terminal.py -v
```

Expected: FAIL (module not found)

**Step 3: Create reporter base**

Create `src/hackmenot/reporters/__init__.py`:
```python
"""Reporters module for hackmenot."""

from hackmenot.reporters.terminal import TerminalReporter

__all__ = ["TerminalReporter"]
```

Create `src/hackmenot/reporters/base.py`:
```python
"""Base reporter interface."""

from abc import ABC, abstractmethod
from hackmenot.core.models import ScanResult


class BaseReporter(ABC):
    """Abstract base class for result reporters."""

    @abstractmethod
    def render(self, result: ScanResult) -> None:
        """Render scan results."""
        pass
```

**Step 4: Create terminal reporter**

Create `src/hackmenot/reporters/terminal.py`:
```python
"""Terminal reporter with Rich colored output."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from hackmenot.core.models import Severity, ScanResult, Finding
from hackmenot.reporters.base import BaseReporter
from hackmenot import __version__


class TerminalReporter(BaseReporter):
    """Rich terminal reporter with colors."""

    SEVERITY_STYLES = {
        Severity.CRITICAL: ("bright_red", "CRITICAL", "bold bright_red"),
        Severity.HIGH: ("yellow", "HIGH", "bold yellow"),
        Severity.MEDIUM: ("bright_yellow", "MEDIUM", "bright_yellow"),
        Severity.LOW: ("green", "LOW", "dim green"),
    }

    SEVERITY_EMOJI = {
        Severity.CRITICAL: "[red]●[/red]",
        Severity.HIGH: "[yellow]●[/yellow]",
        Severity.MEDIUM: "[bright_yellow]●[/bright_yellow]",
        Severity.LOW: "[green]●[/green]",
    }

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def render(self, result: ScanResult) -> None:
        """Render scan results to terminal."""
        self._render_header()

        if result.has_findings:
            self._render_findings(result.findings)
        else:
            self._render_no_findings()

        self._render_summary(result)

    def _render_header(self) -> None:
        """Render the header banner."""
        header = Text()
        header.append("🛡️  ", style="bold")
        header.append("hackmenot", style="bold cyan")
        header.append(f" v{__version__}", style="dim")
        header.append(" - AI-Era Code Security Scanner", style="dim")

        self.console.print()
        self.console.print(header)
        self.console.rule(style="dim")

    def _render_findings(self, findings: list[Finding]) -> None:
        """Render all findings."""
        # Group by file
        by_file: dict[str, list[Finding]] = {}
        for finding in findings:
            by_file.setdefault(finding.file_path, []).append(finding)

        for file_path, file_findings in by_file.items():
            # Sort by line number
            file_findings.sort(key=lambda f: f.line_number)

            for finding in file_findings:
                self._render_finding(finding)

    def _render_finding(self, finding: Finding) -> None:
        """Render a single finding."""
        bg_color, label, label_style = self.SEVERITY_STYLES[finding.severity]

        # Header line
        header = Text()
        header.append("✗ ", style="bold red")
        header.append(label, style=label_style)
        header.append("  ", style="default")
        header.append(finding.file_path, style="cyan")
        header.append(":", style="dim")
        header.append(str(finding.line_number), style="magenta")

        self.console.print()
        self.console.print(Panel(
            header,
            box=box.ROUNDED,
            border_style="dim",
            padding=(0, 1),
        ))

        # Rule info
        rule_line = Text()
        rule_line.append(f"  {finding.rule_id}", style="yellow")
        rule_line.append(": ", style="dim")
        rule_line.append(finding.message, style="default")
        self.console.print(rule_line)

        # Code snippet
        self.console.print()
        code_text = Text()
        code_text.append("    → ", style="yellow")
        code_text.append(finding.code_snippet, style="default on bright_black")
        self.console.print(code_text)

        # Fix suggestion
        if finding.fix_suggestion:
            self.console.print()
            fix_text = Text()
            fix_text.append("    💡 Fix: ", style="bold green")
            fix_text.append(finding.fix_suggestion.split('\n')[0], style="green")
            self.console.print(fix_text)

        # Education
        if finding.education:
            edu_text = Text()
            edu_text.append("    📚 Why: ", style="bold blue")
            edu_text.append(finding.education.split('\n')[0], style="dim italic")
            self.console.print(edu_text)

    def _render_no_findings(self) -> None:
        """Render message when no findings."""
        self.console.print()
        self.console.print(
            "  [bold green]✓ No issues found![/bold green]",
        )

    def _render_summary(self, result: ScanResult) -> None:
        """Render summary section."""
        self.console.print()
        self.console.rule("📊 Summary", style="dim")
        self.console.print()

        # Stats line
        stats = Text()
        stats.append("  Files scanned: ", style="dim")
        stats.append(str(result.files_scanned), style="bold")
        stats.append("    Time: ", style="dim")
        time_style = "green" if result.scan_time_ms < 1000 else "yellow"
        stats.append(f"{result.scan_time_ms:.0f}ms", style=time_style)
        self.console.print(stats)

        # Severity counts
        summary = result.summary_by_severity()

        counts = Text()
        counts.append("  ")
        counts.append(f"{self.SEVERITY_EMOJI[Severity.CRITICAL]} Critical: ", style="default")
        counts.append(str(summary[Severity.CRITICAL]), style="bold red")
        counts.append("  ")
        counts.append(f"{self.SEVERITY_EMOJI[Severity.HIGH]} High: ", style="default")
        counts.append(str(summary[Severity.HIGH]), style="bold yellow")
        counts.append("  ")
        counts.append(f"{self.SEVERITY_EMOJI[Severity.MEDIUM]} Medium: ", style="default")
        counts.append(str(summary[Severity.MEDIUM]), style="bright_yellow")
        counts.append("  ")
        counts.append(f"{self.SEVERITY_EMOJI[Severity.LOW]} Low: ", style="default")
        counts.append(str(summary[Severity.LOW]), style="dim green")

        self.console.print()
        self.console.print(counts)

        # Suggestion
        if result.has_findings:
            self.console.print()
            self.console.print(
                "  [dim]→ Run[/dim] [cyan]hackmenot scan . --fix-interactive[/cyan] [dim]to fix issues[/dim]"
            )

        self.console.print()
```

**Step 5: Run tests**

```bash
pytest tests/test_reporters/test_terminal.py -v
```

Expected: 4 passed

**Step 6: Commit**

```bash
git add -A
git commit -m "feat: add terminal reporter with Rich colored output"
```

---

## Task 8: Scanner Orchestrator

**Files:**
- Create: `src/hackmenot/core/scanner.py`
- Modify: `src/hackmenot/cli/main.py`
- Create: `tests/test_core/test_scanner.py`

**Step 1: Write the failing test**

Create `tests/test_core/test_scanner.py`:
```python
"""Tests for scanner orchestrator."""

import pytest
from pathlib import Path
from hackmenot.core.scanner import Scanner
from hackmenot.core.models import Severity


@pytest.fixture
def scanner():
    return Scanner()


def test_scanner_scans_directory(scanner, tmp_path):
    """Test scanner can scan a directory."""
    # Create test files
    (tmp_path / "good.py").write_text('def hello():\n    return "hi"\n')
    (tmp_path / "bad.py").write_text('query = f"SELECT * FROM users WHERE id = {x}"\n')

    result = scanner.scan([tmp_path])

    assert result.files_scanned >= 2


def test_scanner_finds_vulnerabilities(scanner, tmp_path):
    """Test scanner finds vulnerabilities."""
    bad_file = tmp_path / "vuln.py"
    bad_file.write_text('''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
''')

    result = scanner.scan([tmp_path])

    assert result.has_findings
    assert any(f.rule_id == "INJ001" for f in result.findings)


def test_scanner_respects_severity_filter(scanner, tmp_path):
    """Test scanner can filter by severity."""
    bad_file = tmp_path / "test.py"
    bad_file.write_text('query = f"SELECT * FROM t WHERE x = {y}"\n')

    # Scan with high minimum severity
    result = scanner.scan([tmp_path], min_severity=Severity.CRITICAL)

    # Should still find the critical SQL injection
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


def test_scanner_ignores_non_python_files(scanner, tmp_path):
    """Test scanner ignores non-Python files."""
    (tmp_path / "readme.md").write_text("# Hello\n")
    (tmp_path / "data.json").write_text('{"key": "value"}\n')
    (tmp_path / "test.py").write_text('print("hello")\n')

    result = scanner.scan([tmp_path])

    # Should only scan the .py file
    assert result.files_scanned == 1


def test_scanner_handles_empty_directory(scanner, tmp_path):
    """Test scanner handles empty directory."""
    result = scanner.scan([tmp_path])

    assert result.files_scanned == 0
    assert not result.has_findings
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_core/test_scanner.py -v
```

Expected: FAIL (module not found)

**Step 3: Create scanner**

Create `src/hackmenot/core/scanner.py`:
```python
"""Scanner orchestrator."""

import time
from pathlib import Path

from hackmenot.core.models import Severity, ScanResult, Finding
from hackmenot.parsers.python import PythonParser
from hackmenot.rules.engine import RulesEngine
from hackmenot.rules.registry import RuleRegistry


class Scanner:
    """Main scanner that orchestrates parsing and rule checking."""

    SUPPORTED_EXTENSIONS = {".py"}

    def __init__(self) -> None:
        self.parser = PythonParser()
        self.engine = RulesEngine()
        self._load_rules()

    def _load_rules(self) -> None:
        """Load all built-in rules."""
        registry = RuleRegistry()
        registry.load_all()
        for rule in registry.get_all_rules():
            self.engine.register_rule(rule)

    def scan(
        self,
        paths: list[Path],
        min_severity: Severity = Severity.LOW,
    ) -> ScanResult:
        """Scan paths for security vulnerabilities."""
        start_time = time.time()

        files = self._collect_files(paths)
        findings: list[Finding] = []
        errors: list[str] = []

        for file_path in files:
            try:
                file_findings = self._scan_file(file_path)
                # Filter by severity
                file_findings = [
                    f for f in file_findings if f.severity >= min_severity
                ]
                findings.extend(file_findings)
            except Exception as e:
                errors.append(f"{file_path}: {e}")

        elapsed_ms = (time.time() - start_time) * 1000

        return ScanResult(
            files_scanned=len(files),
            findings=findings,
            scan_time_ms=elapsed_ms,
            errors=errors,
        )

    def _collect_files(self, paths: list[Path]) -> list[Path]:
        """Collect all scannable files from paths."""
        files: list[Path] = []

        for path in paths:
            if path.is_file():
                if path.suffix in self.SUPPORTED_EXTENSIONS:
                    files.append(path)
            elif path.is_dir():
                for ext in self.SUPPORTED_EXTENSIONS:
                    files.extend(path.rglob(f"*{ext}"))

        return sorted(set(files))

    def _scan_file(self, file_path: Path) -> list[Finding]:
        """Scan a single file."""
        parse_result = self.parser.parse_file(file_path)

        if parse_result.has_error:
            return []

        return self.engine.check(parse_result, file_path)
```

**Step 4: Update core __init__.py**

Update `src/hackmenot/core/__init__.py`:
```python
"""Core module for hackmenot."""

from hackmenot.core.models import Severity, Finding, Rule, ScanResult
from hackmenot.core.scanner import Scanner

__all__ = ["Severity", "Finding", "Rule", "ScanResult", "Scanner"]
```

**Step 5: Run tests**

```bash
pytest tests/test_core/test_scanner.py -v
```

Expected: 5 passed

**Step 6: Commit**

```bash
git add -A
git commit -m "feat: add scanner orchestrator that combines parser, rules, and file discovery"
```

---

## Task 9: Wire Up CLI

**Files:**
- Modify: `src/hackmenot/cli/main.py`
- Create: `tests/test_cli/test_scan.py`

**Step 1: Write the failing test**

Create `tests/test_cli/test_scan.py`:
```python
"""Tests for scan command."""

import pytest
from pathlib import Path
from typer.testing import CliRunner
from hackmenot.cli.main import app

runner = CliRunner()


@pytest.fixture
def vuln_project(tmp_path):
    """Create a project with vulnerabilities."""
    (tmp_path / "api.py").write_text('''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
''')
    return tmp_path


@pytest.fixture
def clean_project(tmp_path):
    """Create a project without vulnerabilities."""
    (tmp_path / "main.py").write_text('''
def hello(name: str) -> str:
    return f"Hello, {name}!"
''')
    return tmp_path


def test_scan_finds_vulnerabilities(vuln_project):
    """Test scan command finds vulnerabilities."""
    result = runner.invoke(app, ["scan", str(vuln_project)])

    assert result.exit_code == 1  # Non-zero for findings
    assert "INJ001" in result.stdout


def test_scan_clean_project_succeeds(clean_project):
    """Test scan command succeeds on clean code."""
    result = runner.invoke(app, ["scan", str(clean_project)])

    assert result.exit_code == 0


def test_scan_json_output(vuln_project):
    """Test scan with JSON output format."""
    result = runner.invoke(app, ["scan", str(vuln_project), "--format", "json"])

    assert result.exit_code == 1
    assert '"rule_id"' in result.stdout or "INJ001" in result.stdout


def test_scan_with_severity_filter(vuln_project):
    """Test scan with severity filter."""
    result = runner.invoke(app, [
        "scan", str(vuln_project),
        "--severity", "critical"
    ])

    # Should still exit non-zero since INJ001 is critical
    assert result.exit_code == 1
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_cli/test_scan.py -v
```

Expected: FAIL (features not implemented)

**Step 3: Update CLI main**

Update `src/hackmenot/cli/main.py`:
```python
"""Main CLI entry point using Typer."""

import json
import sys
from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from hackmenot import __version__
from hackmenot.core.models import Severity, ScanResult
from hackmenot.core.scanner import Scanner
from hackmenot.reporters.terminal import TerminalReporter

app = typer.Typer(
    name="hackmenot",
    help="AI-Era Code Security Scanner",
    add_completion=False,
)
console = Console()


class OutputFormat(str, Enum):
    """Output format options."""
    terminal = "terminal"
    json = "json"
    sarif = "sarif"


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"hackmenot {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """hackmenot - AI-Era Code Security Scanner."""
    pass


@app.command()
def scan(
    paths: list[Path] = typer.Argument(
        ...,
        help="Paths to scan (files or directories)",
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.terminal,
        "--format",
        "-f",
        help="Output format",
    ),
    severity: str = typer.Option(
        "low",
        "--severity",
        "-s",
        help="Minimum severity to report: critical, high, medium, low",
    ),
    fail_on: str = typer.Option(
        "high",
        "--fail-on",
        help="Minimum severity to return non-zero exit code",
    ),
) -> None:
    """Scan code for security vulnerabilities."""
    # Validate paths exist
    for path in paths:
        if not path.exists():
            console.print(f"[red]Error: Path does not exist: {path}[/red]")
            raise typer.Exit(1)

    # Parse severity levels
    try:
        min_severity = Severity.from_string(severity)
        fail_severity = Severity.from_string(fail_on)
    except KeyError as e:
        console.print(f"[red]Error: Invalid severity level: {e}[/red]")
        raise typer.Exit(1)

    # Run scan
    scanner = Scanner()
    result = scanner.scan(paths, min_severity=min_severity)

    # Output results
    if format == OutputFormat.terminal:
        reporter = TerminalReporter(console=console)
        reporter.render(result)
    elif format == OutputFormat.json:
        _output_json(result)
    elif format == OutputFormat.sarif:
        console.print("[yellow]SARIF output not yet implemented[/yellow]")
        _output_json(result)

    # Exit code based on findings
    if result.findings_at_or_above(fail_severity):
        raise typer.Exit(1)


def _output_json(result: ScanResult) -> None:
    """Output results as JSON."""
    data = {
        "files_scanned": result.files_scanned,
        "scan_time_ms": result.scan_time_ms,
        "findings": [
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "severity": str(f.severity),
                "message": f.message,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "column": f.column,
                "code_snippet": f.code_snippet,
                "fix_suggestion": f.fix_suggestion,
                "education": f.education,
            }
            for f in result.findings
        ],
        "summary": {
            str(sev): count
            for sev, count in result.summary_by_severity().items()
        },
    }
    print(json.dumps(data, indent=2))


@app.command()
def rules(
    show_id: Optional[str] = typer.Argument(
        None,
        help="Rule ID to show details for",
    ),
) -> None:
    """List available security rules."""
    from hackmenot.rules.registry import RuleRegistry

    registry = RuleRegistry()
    registry.load_all()

    if show_id:
        rule = registry.get_rule(show_id)
        if rule:
            console.print(f"\n[bold cyan]{rule.id}[/bold cyan]: {rule.name}")
            console.print(f"[dim]Severity:[/dim] {rule.severity}")
            console.print(f"[dim]Category:[/dim] {rule.category}")
            console.print(f"\n{rule.description}")
            if rule.education:
                console.print(f"\n[blue]Education:[/blue]\n{rule.education}")
        else:
            console.print(f"[red]Rule not found: {show_id}[/red]")
    else:
        console.print("\n[bold]Available Rules[/bold]\n")
        for rule in registry.get_all_rules():
            sev_color = {
                Severity.CRITICAL: "red",
                Severity.HIGH: "yellow",
                Severity.MEDIUM: "bright_yellow",
                Severity.LOW: "green",
            }[rule.severity]
            console.print(
                f"  [{sev_color}]{rule.severity.name:8}[/{sev_color}] "
                f"[cyan]{rule.id}[/cyan] - {rule.name}"
            )
```

**Step 4: Run tests**

```bash
pytest tests/test_cli/test_scan.py -v
```

Expected: 4 passed

**Step 5: Run all tests**

```bash
pytest -v
```

Expected: All tests pass

**Step 6: Test manually**

```bash
# Test on the project itself
hackmenot scan .

# Create a test file with vulnerability
echo 'query = f"SELECT * FROM users WHERE id = {x}"' > /tmp/test.py
hackmenot scan /tmp/test.py
hackmenot scan /tmp/test.py --format json

# Test rules list
hackmenot rules
hackmenot rules INJ001
```

**Step 7: Commit**

```bash
git add -A
git commit -m "feat: wire up CLI with scan command, JSON output, and rules listing"
```

---

## Task 10: Basic Caching

**Files:**
- Create: `src/hackmenot/core/cache.py`
- Modify: `src/hackmenot/core/scanner.py`
- Create: `tests/test_core/test_cache.py`

**Step 1: Write the failing test**

Create `tests/test_core/test_cache.py`:
```python
"""Tests for file caching."""

import pytest
from pathlib import Path
from hackmenot.core.cache import FileCache


@pytest.fixture
def cache(tmp_path):
    cache_dir = tmp_path / ".hackmenot_cache"
    return FileCache(cache_dir)


def test_cache_stores_and_retrieves(cache, tmp_path):
    """Test cache stores and retrieves results."""
    test_file = tmp_path / "test.py"
    test_file.write_text("print('hello')")

    findings = [{"rule_id": "TEST001", "line": 1}]

    cache.store(test_file, findings)
    result = cache.get(test_file)

    assert result == findings


def test_cache_invalidates_on_file_change(cache, tmp_path):
    """Test cache invalidates when file changes."""
    test_file = tmp_path / "test.py"
    test_file.write_text("print('hello')")

    cache.store(test_file, [{"rule_id": "TEST001"}])

    # Modify file
    test_file.write_text("print('world')")

    result = cache.get(test_file)
    assert result is None


def test_cache_returns_none_for_uncached(cache, tmp_path):
    """Test cache returns None for uncached files."""
    test_file = tmp_path / "uncached.py"
    test_file.write_text("x = 1")

    result = cache.get(test_file)
    assert result is None
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_core/test_cache.py -v
```

Expected: FAIL (module not found)

**Step 3: Create cache**

Create `src/hackmenot/core/cache.py`:
```python
"""File caching for incremental scans."""

import hashlib
import json
from pathlib import Path
from typing import Any


class FileCache:
    """Cache for storing scan results by file hash."""

    def __init__(self, cache_dir: Path | None = None) -> None:
        self.cache_dir = cache_dir or self._default_cache_dir()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, tuple[str, Any]] = {}
        self._load_cache()

    def _default_cache_dir(self) -> Path:
        """Get default cache directory."""
        return Path.home() / ".hackmenot" / "cache"

    def _load_cache(self) -> None:
        """Load cache from disk."""
        cache_file = self.cache_dir / "scan_cache.json"
        if cache_file.exists():
            try:
                with open(cache_file) as f:
                    data = json.load(f)
                    self._cache = {k: tuple(v) for k, v in data.items()}
            except Exception:
                self._cache = {}

    def _save_cache(self) -> None:
        """Save cache to disk."""
        cache_file = self.cache_dir / "scan_cache.json"
        try:
            with open(cache_file, "w") as f:
                json.dump({k: list(v) for k, v in self._cache.items()}, f)
        except Exception:
            pass  # Fail silently for cache writes

    def _file_hash(self, file_path: Path) -> str:
        """Compute hash of file contents."""
        content = file_path.read_bytes()
        return hashlib.sha256(content).hexdigest()

    def get(self, file_path: Path) -> Any | None:
        """Get cached results for a file, or None if not cached/stale."""
        key = str(file_path.absolute())

        if key not in self._cache:
            return None

        stored_hash, findings = self._cache[key]
        current_hash = self._file_hash(file_path)

        if stored_hash != current_hash:
            # File changed, invalidate cache
            del self._cache[key]
            return None

        return findings

    def store(self, file_path: Path, findings: Any) -> None:
        """Store results for a file."""
        key = str(file_path.absolute())
        file_hash = self._file_hash(file_path)
        self._cache[key] = (file_hash, findings)
        self._save_cache()

    def clear(self) -> None:
        """Clear all cached results."""
        self._cache = {}
        cache_file = self.cache_dir / "scan_cache.json"
        if cache_file.exists():
            cache_file.unlink()
```

**Step 4: Run tests**

```bash
pytest tests/test_core/test_cache.py -v
```

Expected: 3 passed

**Step 5: Update core __init__.py**

Update `src/hackmenot/core/__init__.py`:
```python
"""Core module for hackmenot."""

from hackmenot.core.models import Severity, Finding, Rule, ScanResult
from hackmenot.core.scanner import Scanner
from hackmenot.core.cache import FileCache

__all__ = ["Severity", "Finding", "Rule", "ScanResult", "Scanner", "FileCache"]
```

**Step 6: Run all tests**

```bash
pytest -v
```

Expected: All tests pass

**Step 7: Commit**

```bash
git add -A
git commit -m "feat: add file caching for incremental scans"
```

---

## Task 11: Final Integration Test & Polish

**Files:**
- Create: `tests/test_integration.py`

**Step 1: Create integration test**

Create `tests/test_integration.py`:
```python
"""Integration tests for end-to-end scanning."""

import pytest
from pathlib import Path
from typer.testing import CliRunner
from hackmenot.cli.main import app

runner = CliRunner()


@pytest.fixture
def sample_project(tmp_path):
    """Create a realistic sample project."""
    # Create directory structure
    src = tmp_path / "src"
    src.mkdir()

    # Good file
    (src / "utils.py").write_text('''
"""Utility functions."""

def format_name(first: str, last: str) -> str:
    """Format a full name."""
    return f"{first} {last}"
''')

    # File with SQL injection
    (src / "database.py").write_text('''
"""Database operations."""

def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return execute(query)

def get_all_users():
    return execute("SELECT * FROM users")
''')

    # File with missing auth
    (src / "api.py").write_text('''
"""API endpoints."""
from flask import Flask
app = Flask(__name__)

@app.route("/users")
def list_users():
    return get_all_users()

@app.route("/health")
def health():
    return "ok"
''')

    return tmp_path


def test_full_scan_workflow(sample_project):
    """Test complete scan workflow."""
    result = runner.invoke(app, ["scan", str(sample_project)])

    # Should find issues
    assert result.exit_code == 1

    # Should report SQL injection
    assert "INJ001" in result.stdout

    # Should report missing auth
    assert "AUTH001" in result.stdout

    # Should show summary
    assert "Critical" in result.stdout or "critical" in result.stdout.lower()


def test_scan_specific_file(sample_project):
    """Test scanning a specific file."""
    result = runner.invoke(app, [
        "scan",
        str(sample_project / "src" / "utils.py")
    ])

    # Clean file should pass
    assert result.exit_code == 0


def test_json_output_valid(sample_project):
    """Test JSON output is valid."""
    import json

    result = runner.invoke(app, [
        "scan",
        str(sample_project),
        "--format", "json"
    ])

    # Should be valid JSON
    data = json.loads(result.stdout)
    assert "files_scanned" in data
    assert "findings" in data
    assert isinstance(data["findings"], list)


def test_severity_filtering(sample_project):
    """Test severity filtering works."""
    # With high severity filter, should still find critical SQL injection
    result = runner.invoke(app, [
        "scan",
        str(sample_project),
        "--severity", "high"
    ])

    assert result.exit_code == 1
    assert "INJ001" in result.stdout


def test_rules_command():
    """Test rules listing command."""
    result = runner.invoke(app, ["rules"])

    assert result.exit_code == 0
    assert "INJ001" in result.stdout
    assert "AUTH001" in result.stdout


def test_rules_show_specific():
    """Test showing specific rule."""
    result = runner.invoke(app, ["rules", "INJ001"])

    assert result.exit_code == 0
    assert "SQL" in result.stdout or "injection" in result.stdout.lower()
```

**Step 2: Run integration tests**

```bash
pytest tests/test_integration.py -v
```

Expected: 6 passed

**Step 3: Run full test suite**

```bash
pytest -v --tb=short
```

Expected: All tests pass

**Step 4: Test manually**

```bash
# Version
hackmenot --version

# Scan current directory
hackmenot scan .

# List rules
hackmenot rules

# Show specific rule
hackmenot rules INJ001

# Create vulnerable file and scan
mkdir -p /tmp/testproj
cat > /tmp/testproj/app.py << 'EOF'
from flask import Flask
app = Flask(__name__)

@app.route("/users/<id>")
def get_user(id):
    query = f"SELECT * FROM users WHERE id = {id}"
    return db.execute(query)
EOF

hackmenot scan /tmp/testproj
hackmenot scan /tmp/testproj --format json
```

**Step 5: Final commit**

```bash
git add -A
git commit -m "feat: add integration tests and complete Phase 1 MVP"
```

---

## Summary

**Phase 1 Complete!** You now have:

- ✅ Working `hackmenot scan .` command
- ✅ Python AST parser
- ✅ Rules engine with 10 built-in rules
- ✅ Colored terminal output with Rich
- ✅ JSON output format
- ✅ Basic file caching
- ✅ Full test suite

**To run:**
```bash
pip install -e ".[dev]"
hackmenot scan .
```

**Next: Phase 2** - Complete Python ruleset, fix engine, SARIF output, config file support.
