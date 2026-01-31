"""Tests for rule registry parsing."""

from pathlib import Path

import pytest

from hackmenot.core.models import FixConfig, Severity
from hackmenot.rules.registry import RuleRegistry


@pytest.fixture
def temp_rules_dir(tmp_path: Path) -> Path:
    """Create a temporary rules directory."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    return rules_dir


def test_parse_rule_with_old_fix_template_format(temp_rules_dir: Path):
    """Test parsing rule with old fix_template string format."""
    rule_file = temp_rules_dir / "test_rule.yml"
    rule_file.write_text("""
id: TEST001
name: test-rule
severity: high
category: test
languages:
  - python
message: Test message
pattern:
  type: fstring
  contains:
    - SELECT
fix_template: "Use parameterized queries"
education: "This is educational content"
""")

    registry = RuleRegistry(rules_dir=temp_rules_dir)
    registry.load_all()

    rule = registry.get_rule("TEST001")
    assert rule is not None
    assert rule.fix.template == "Use parameterized queries"
    assert rule.fix.pattern == ""
    assert rule.fix.replacement == ""


def test_parse_rule_with_new_fix_dict_format(temp_rules_dir: Path):
    """Test parsing rule with new fix dict format including pattern/replacement."""
    rule_file = temp_rules_dir / "test_rule.yml"
    rule_file.write_text("""
id: TEST002
name: test-rule-new
severity: critical
category: injection
languages:
  - python
message: SQL injection detected
pattern:
  type: fstring
  contains:
    - SELECT
fix:
  template: "Use parameterized queries instead"
  pattern: 'f"SELECT * FROM {table} WHERE id = {user_id}"'
  replacement: 'cursor.execute("SELECT * FROM ? WHERE id = ?", (table, user_id))'
education: "SQL injection education"
""")

    registry = RuleRegistry(rules_dir=temp_rules_dir)
    registry.load_all()

    rule = registry.get_rule("TEST002")
    assert rule is not None
    assert rule.fix.template == "Use parameterized queries instead"
    assert rule.fix.pattern == 'f"SELECT * FROM {table} WHERE id = {user_id}"'
    assert rule.fix.replacement == 'cursor.execute("SELECT * FROM ? WHERE id = ?", (table, user_id))'


def test_parse_rule_with_fix_dict_template_only(temp_rules_dir: Path):
    """Test parsing rule with fix dict containing only template."""
    rule_file = temp_rules_dir / "test_rule.yml"
    rule_file.write_text("""
id: TEST003
name: test-rule-partial
severity: medium
category: test
languages:
  - python
message: Test message
pattern:
  type: fstring
fix:
  template: "Just a template"
""")

    registry = RuleRegistry(rules_dir=temp_rules_dir)
    registry.load_all()

    rule = registry.get_rule("TEST003")
    assert rule is not None
    assert rule.fix.template == "Just a template"
    assert rule.fix.pattern == ""
    assert rule.fix.replacement == ""


def test_parse_rule_without_fix(temp_rules_dir: Path):
    """Test parsing rule without any fix specification."""
    rule_file = temp_rules_dir / "test_rule.yml"
    rule_file.write_text("""
id: TEST004
name: test-rule-no-fix
severity: low
category: test
languages:
  - python
message: Test message
pattern:
  type: fstring
""")

    registry = RuleRegistry(rules_dir=temp_rules_dir)
    registry.load_all()

    rule = registry.get_rule("TEST004")
    assert rule is not None
    assert rule.fix.template == ""
    assert rule.fix.pattern == ""
    assert rule.fix.replacement == ""


def test_parse_rule_basic_fields(temp_rules_dir: Path):
    """Test basic rule fields are parsed correctly."""
    rule_file = temp_rules_dir / "test_rule.yml"
    rule_file.write_text("""
id: TEST005
name: test-basic
severity: critical
category: security
languages:
  - python
  - javascript
description: A test rule description
message: Found a vulnerability
pattern:
  type: call
  names:
    - eval
education: "Don't use eval"
references:
  - https://example.com/security
""")

    registry = RuleRegistry(rules_dir=temp_rules_dir)
    registry.load_all()

    rule = registry.get_rule("TEST005")
    assert rule is not None
    assert rule.id == "TEST005"
    assert rule.name == "test-basic"
    assert rule.severity == Severity.CRITICAL
    assert rule.category == "security"
    assert "python" in rule.languages
    assert "javascript" in rule.languages
    assert rule.description == "A test rule description"
    assert rule.message == "Found a vulnerability"
    assert rule.education == "Don't use eval"
    assert "https://example.com/security" in rule.references


def test_registry_loads_multiple_rules(temp_rules_dir: Path):
    """Test registry can load multiple rule files."""
    rule1 = temp_rules_dir / "rule1.yml"
    rule1.write_text("""
id: RULE001
name: rule-one
severity: high
category: test
languages: [python]
message: Rule one
pattern: {}
""")

    rule2 = temp_rules_dir / "rule2.yaml"
    rule2.write_text("""
id: RULE002
name: rule-two
severity: medium
category: test
languages: [python]
message: Rule two
pattern: {}
fix_template: "Fix for rule two"
""")

    registry = RuleRegistry(rules_dir=temp_rules_dir)
    registry.load_all()

    assert registry.get_rule("RULE001") is not None
    assert registry.get_rule("RULE002") is not None
    assert registry.get_rule("RULE002").fix.template == "Fix for rule two"

    all_rules = list(registry.get_all_rules())
    assert len(all_rules) == 2


def test_registry_handles_empty_directory(temp_rules_dir: Path):
    """Test registry handles empty rules directory gracefully."""
    registry = RuleRegistry(rules_dir=temp_rules_dir)
    registry.load_all()

    all_rules = list(registry.get_all_rules())
    assert len(all_rules) == 0


def test_registry_handles_nonexistent_directory(tmp_path: Path):
    """Test registry handles nonexistent directory gracefully."""
    nonexistent = tmp_path / "nonexistent"
    registry = RuleRegistry(rules_dir=nonexistent)
    registry.load_all()  # Should not raise

    all_rules = list(registry.get_all_rules())
    assert len(all_rules) == 0
