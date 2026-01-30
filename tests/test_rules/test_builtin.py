"""Tests for built-in rules."""

from pathlib import Path

from hackmenot.parsers.python import PythonParser
from hackmenot.rules.engine import RulesEngine
from hackmenot.rules.registry import RuleRegistry


def test_registry_loads_builtin_rules():
    """Test registry loads all built-in rules."""
    registry = RuleRegistry()
    registry.load_all()
    rules = list(registry.get_all_rules())
    assert len(rules) >= 10


def test_inj001_detects_sql_fstring(tmp_path: Path):
    """Test INJ001 detects SQL injection via f-string."""
    registry = RuleRegistry()
    registry.load_all()

    engine = RulesEngine()
    for rule in registry.get_all_rules():
        engine.register_rule(rule)

    parser = PythonParser()

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


def test_auth001_detects_missing_auth(tmp_path: Path):
    """Test AUTH001 detects missing auth decorator."""
    registry = RuleRegistry()
    registry.load_all()

    engine = RulesEngine()
    for rule in registry.get_all_rules():
        engine.register_rule(rule)

    parser = PythonParser()

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


def test_clean_code_has_no_findings(tmp_path: Path):
    """Test clean code produces no findings."""
    registry = RuleRegistry()
    registry.load_all()

    engine = RulesEngine()
    for rule in registry.get_all_rules():
        engine.register_rule(rule)

    parser = PythonParser()

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
