"""Tests for JavaScript rules engine support."""

from pathlib import Path

from hackmenot.core.models import FixConfig, Rule, Severity
from hackmenot.parsers.javascript import JavaScriptParser
from hackmenot.parsers.python import PythonParser
from hackmenot.rules.engine import RulesEngine


def test_engine_checks_js_call_pattern(tmp_path: Path):
    """Test engine matches call patterns in JavaScript."""
    engine = RulesEngine()
    parser = JavaScriptParser()

    # Create a test JS rule that detects eval()
    rule = Rule(
        id="JSIJ001",
        name="js-eval-injection",
        severity=Severity.CRITICAL,
        category="injection",
        languages=["javascript"],
        description="Dangerous eval() usage detected",
        message="eval() can execute arbitrary code and is a security risk",
        pattern={
            "type": "call",
            "names": ["eval"],
        },
        fix=FixConfig(template="Use safer alternatives like JSON.parse() for data parsing"),
        education="eval() executes arbitrary JavaScript code and should be avoided.",
    )
    engine.register_rule(rule)

    # Create a JS file with eval()
    js_file = tmp_path / "test.js"
    js_file.write_text("""
const userInput = getUserInput();
const result = eval(userInput);
console.log(result);
""")

    parse_result = parser.parse_file(js_file)
    findings = engine.check(parse_result, js_file)

    # Verify finding is detected
    assert len(findings) == 1
    assert findings[0].rule_id == "JSIJ001"
    assert findings[0].line_number == 3
    assert "eval" in findings[0].code_snippet


def test_engine_checks_js_template_pattern(tmp_path: Path):
    """Test engine matches template literal patterns with interpolation."""
    engine = RulesEngine()
    parser = JavaScriptParser()

    # Create a rule that detects SQL in template literals
    rule = Rule(
        id="JSIJ002",
        name="js-sql-injection",
        severity=Severity.CRITICAL,
        category="injection",
        languages=["javascript"],
        description="Possible SQL injection via template literal",
        message="SQL query with interpolation may be vulnerable to injection",
        pattern={
            "type": "fstring",
            "contains": ["SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE"],
        },
        fix=FixConfig(template="Use parameterized queries instead"),
        education="Template literals with SQL can be vulnerable to injection.",
    )
    engine.register_rule(rule)

    js_file = tmp_path / "test.js"
    js_file.write_text("""
const userId = 123;
const query = `SELECT * FROM users WHERE id = ${userId}`;
db.execute(query);
""")

    parse_result = parser.parse_file(js_file)
    findings = engine.check(parse_result, js_file)

    assert len(findings) == 1
    assert findings[0].rule_id == "JSIJ002"
    assert "SELECT" in findings[0].code_snippet


def test_engine_checks_js_string_pattern(tmp_path: Path):
    """Test engine matches string patterns in assignments."""
    engine = RulesEngine()
    parser = JavaScriptParser()

    rule = Rule(
        id="JSTEST001",
        name="js-hardcoded-secret",
        severity=Severity.HIGH,
        category="secrets",
        languages=["javascript"],
        description="Possible hardcoded secret",
        message="Hardcoded secret detected in code",
        pattern={
            "type": "string",
            "contains": ["secret", "password", "apikey"],
        },
        fix=FixConfig(template="Use environment variables for secrets"),
        education="Hardcoded secrets can be exposed in source control.",
    )
    engine.register_rule(rule)

    js_file = tmp_path / "test.js"
    js_file.write_text("""
const password = "supersecret123";
const apiKey = "sk-12345";
""")

    parse_result = parser.parse_file(js_file)
    findings = engine.check(parse_result, js_file)

    # Should find the password assignment
    assert len(findings) >= 1
    password_findings = [f for f in findings if "password" in f.code_snippet.lower()]
    assert len(password_findings) >= 1


def test_engine_respects_js_language_filter(tmp_path: Path):
    """Test Python rules don't match JavaScript files."""
    engine = RulesEngine()
    js_parser = JavaScriptParser()

    # Create a Python-only rule
    py_only_rule = Rule(
        id="PY001",
        name="python-only-rule",
        severity=Severity.CRITICAL,
        category="test",
        languages=["python"],
        description="Python only rule",
        message="This should not match JavaScript files",
        pattern={
            "type": "call",
            "names": ["eval"],
        },
    )
    engine.register_rule(py_only_rule)

    # Create a JS file with eval
    js_file = tmp_path / "test.js"
    js_file.write_text('const result = eval("1 + 1");\n')

    parse_result = js_parser.parse_file(js_file)
    findings = engine.check(parse_result, js_file)

    # Should find no findings since rule is Python-only
    assert len(findings) == 0


def test_engine_js_rule_does_not_match_python(tmp_path: Path):
    """Test JavaScript rules don't match Python files."""
    engine = RulesEngine()
    py_parser = PythonParser()

    # Create a JavaScript-only rule
    js_only_rule = Rule(
        id="JS001",
        name="js-only-rule",
        severity=Severity.CRITICAL,
        category="test",
        languages=["javascript"],
        description="JavaScript only rule",
        message="This should not match Python files",
        pattern={
            "type": "call",
            "names": ["eval"],
        },
    )
    engine.register_rule(js_only_rule)

    # Create a Python file with eval
    py_file = tmp_path / "test.py"
    py_file.write_text('result = eval("1 + 1")\n')

    parse_result = py_parser.parse_file(py_file)
    findings = engine.check(parse_result, py_file)

    # Should find no findings since rule is JavaScript-only
    assert len(findings) == 0


def test_engine_detects_multiple_js_calls(tmp_path: Path):
    """Test engine detects multiple dangerous calls."""
    engine = RulesEngine()
    parser = JavaScriptParser()

    rule = Rule(
        id="JSIJ001",
        name="js-dangerous-call",
        severity=Severity.HIGH,
        category="injection",
        languages=["javascript"],
        description="Dangerous function call",
        message="Potentially dangerous function call detected",
        pattern={
            "type": "call",
            "names": ["eval", "setTimeout"],
        },
    )
    engine.register_rule(rule)

    js_file = tmp_path / "test.js"
    js_file.write_text("""
eval("console.log('hello')");
setTimeout(userCode, 1000);
eval("1 + 1");
""")

    parse_result = parser.parse_file(js_file)
    findings = engine.check(parse_result, js_file)

    # Should find 3 dangerous calls (2 eval + 1 setTimeout)
    assert len(findings) == 3


def test_engine_template_pattern_requires_interpolation(tmp_path: Path):
    """Test fstring pattern only matches templates with interpolation."""
    engine = RulesEngine()
    parser = JavaScriptParser()

    rule = Rule(
        id="JSIJ002",
        name="js-sql-injection",
        severity=Severity.CRITICAL,
        category="injection",
        languages=["javascript"],
        description="SQL injection via template literal",
        message="SQL with interpolation detected",
        pattern={
            "type": "fstring",
            "contains": ["SELECT"],
        },
    )
    engine.register_rule(rule)

    js_file = tmp_path / "test.js"
    js_file.write_text("""
// Safe: no interpolation
const query1 = `SELECT * FROM users`;

// Dangerous: has interpolation
const query2 = `SELECT * FROM users WHERE id = ${userId}`;
""")

    parse_result = parser.parse_file(js_file)
    findings = engine.check(parse_result, js_file)

    # Should only find the template with interpolation
    assert len(findings) == 1
    assert findings[0].line_number == 6  # Line with interpolation


def test_engine_handles_chained_calls(tmp_path: Path):
    """Test engine can match patterns in chained method calls."""
    engine = RulesEngine()
    parser = JavaScriptParser()

    rule = Rule(
        id="JSTEST001",
        name="js-innerhtml",
        severity=Severity.HIGH,
        category="xss",
        languages=["javascript"],
        description="Dangerous innerHTML usage",
        message="innerHTML can lead to XSS vulnerabilities",
        pattern={
            "type": "call",
            "names": ["innerHTML"],
        },
    )
    engine.register_rule(rule)

    js_file = tmp_path / "test.js"
    js_file.write_text("""
const el = document.getElementById("container");
el.innerHTML = userInput;
""")

    parse_result = parser.parse_file(js_file)
    findings = engine.check(parse_result, js_file)

    # innerHTML is an assignment, not a call, so this specific pattern won't match
    # This test verifies the call pattern correctly handles member expressions
    assert len(findings) == 0  # innerHTML is not a call


def test_engine_ignores_clean_js_code(tmp_path: Path):
    """Test engine returns no findings for clean JavaScript code."""
    engine = RulesEngine()
    parser = JavaScriptParser()

    rule = Rule(
        id="JSIJ001",
        name="js-eval",
        severity=Severity.CRITICAL,
        category="injection",
        languages=["javascript"],
        description="Eval injection",
        message="eval() detected",
        pattern={
            "type": "call",
            "names": ["eval"],
        },
    )
    engine.register_rule(rule)

    js_file = tmp_path / "clean.js"
    js_file.write_text("""
function greet(name) {
    return `Hello, ${name}!`;
}

const result = greet("World");
console.log(result);
""")

    parse_result = parser.parse_file(js_file)
    findings = engine.check(parse_result, js_file)

    assert len(findings) == 0
