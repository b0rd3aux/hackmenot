"""Tests for rules engine."""

from pathlib import Path

from hackmenot.core.models import Rule, Severity
from hackmenot.parsers.python import PythonParser
from hackmenot.rules.engine import RulesEngine


def test_engine_can_register_rule():
    """Test engine can register a rule."""
    engine = RulesEngine()
    rule = Rule(
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
        education=(
            "AI often generates SQL queries using f-strings for simplicity, "
            "but this is vulnerable to SQL injection."
        ),
    )
    engine.register_rule(rule)
    assert rule.id in engine.rules


def test_engine_can_check_file(fixtures_dir: Path):
    """Test engine can check a file against rules."""
    engine = RulesEngine()
    parser = PythonParser()

    rule = Rule(
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
        education=(
            "AI often generates SQL queries using f-strings for simplicity, "
            "but this is vulnerable to SQL injection."
        ),
    )
    engine.register_rule(rule)

    file_path = fixtures_dir / "python" / "simple_function.py"
    parse_result = parser.parse_file(file_path)

    findings = engine.check(parse_result, file_path)

    # Should find SQL injection in f-strings
    assert len(findings) >= 1
    assert findings[0].rule_id == "INJ001"


def test_engine_returns_empty_for_clean_code(tmp_path: Path):
    """Test engine returns no findings for clean code."""
    engine = RulesEngine()
    parser = PythonParser()

    rule = Rule(
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
        education=(
            "AI often generates SQL queries using f-strings for simplicity, "
            "but this is vulnerable to SQL injection."
        ),
    )
    engine.register_rule(rule)

    clean_file = tmp_path / "clean.py"
    clean_file.write_text('def hello():\n    return "Hello, World!"\n')

    parse_result = parser.parse_file(clean_file)
    findings = engine.check(parse_result, clean_file)

    assert len(findings) == 0


def test_engine_skips_rules_for_other_languages(tmp_path: Path):
    """Test engine skips rules not matching file language."""
    engine = RulesEngine()
    parser = PythonParser()

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
