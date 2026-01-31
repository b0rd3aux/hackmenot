"""Tests for FixEngine."""

from hackmenot.core.models import Finding, FixConfig, Rule, Severity
from hackmenot.fixes.engine import FixEngine, FixResult


def test_fix_engine_applies_template():
    """Test that FixEngine applies fix_suggestion to source."""
    source = """\
def get_user():
    return db.query(User)
"""
    finding = Finding(
        rule_id="AUTH001",
        rule_name="missing-auth",
        severity=Severity.HIGH,
        message="Missing authentication",
        file_path="src/api.py",
        line_number=1,
        column=0,
        code_snippet="def get_user():",
        fix_suggestion="@login_required\ndef get_user():",
        education="AI often skips auth checks",
    )

    engine = FixEngine()
    result = engine.apply_fix(source, finding)

    assert result.applied is True
    assert result.reason == "success"
    assert "@login_required" in result.fixed
    assert "def get_user():" in result.fixed


def test_fix_engine_returns_no_fix_defined_when_no_fix():
    """Test that FixEngine returns FixResult with no_fix_defined if no fix."""
    source = """\
def get_user():
    return db.query(User)
"""
    finding = Finding(
        rule_id="AUTH001",
        rule_name="missing-auth",
        severity=Severity.HIGH,
        message="Missing authentication",
        file_path="src/api.py",
        line_number=1,
        column=0,
        code_snippet="def get_user():",
        fix_suggestion="",
        education="AI often skips auth checks",
    )

    engine = FixEngine()
    result = engine.apply_fix(source, finding)

    assert result.applied is False
    assert result.reason == "no_fix_defined"


def test_fix_engine_preserves_other_lines():
    """Test that FixEngine preserves other code untouched."""
    source = """\
import os

def get_user():
    return db.query(User)

def delete_user():
    pass
"""
    finding = Finding(
        rule_id="AUTH001",
        rule_name="missing-auth",
        severity=Severity.HIGH,
        message="Missing authentication",
        file_path="src/api.py",
        line_number=4,
        column=0,
        code_snippet="def get_user():",
        fix_suggestion="@login_required\ndef get_user():",
        education="AI often skips auth checks",
    )

    engine = FixEngine()
    result = engine.apply_fix(source, finding)

    assert result.applied is True
    assert "@login_required" in result.fixed
    assert "def get_user():" in result.fixed


def test_fix_engine_preserves_indentation():
    """Test that FixEngine preserves indentation."""
    source = """\
class UserAPI:
    def get_user(self):
        return db.query(User)
"""
    finding = Finding(
        rule_id="AUTH001",
        rule_name="missing-auth",
        severity=Severity.HIGH,
        message="Missing authentication",
        file_path="src/api.py",
        line_number=2,
        column=4,
        code_snippet="    def get_user(self):",
        fix_suggestion="@login_required\ndef get_user(self):",
        education="AI often skips auth checks",
    )

    engine = FixEngine()
    result = engine.apply_fix(source, finding)

    assert result.applied is True
    # The decorator and function should be indented
    assert "    @login_required" in result.fixed
    assert "    def get_user(self):" in result.fixed


def test_apply_fixes_multiple():
    """Test applying multiple fixes from bottom to top."""
    source = """\
def get_user():
    pass

def delete_user():
    pass
"""
    findings = [
        Finding(
            rule_id="AUTH001",
            rule_name="missing-auth",
            severity=Severity.HIGH,
            message="Missing auth",
            file_path="src/api.py",
            line_number=1,
            column=0,
            code_snippet="def get_user():",
            fix_suggestion="@login_required\ndef get_user():",
            education="",
        ),
        Finding(
            rule_id="AUTH001",
            rule_name="missing-auth",
            severity=Severity.HIGH,
            message="Missing auth",
            file_path="src/api.py",
            line_number=4,
            column=0,
            code_snippet="def delete_user():",
            fix_suggestion="@login_required\ndef delete_user():",
            education="",
        ),
    ]

    engine = FixEngine()
    result, count = engine.apply_fixes(source, findings)

    assert count == 2
    assert result.count("@login_required") == 2


def test_apply_fixes_skips_no_fix():
    """Test that apply_fixes skips findings with no fix_suggestion."""
    source = """\
def get_user():
    pass
"""
    findings = [
        Finding(
            rule_id="AUTH001",
            rule_name="missing-auth",
            severity=Severity.HIGH,
            message="Missing auth",
            file_path="src/api.py",
            line_number=1,
            column=0,
            code_snippet="def get_user():",
            fix_suggestion="",
            education="",
        ),
    ]

    engine = FixEngine()
    result, count = engine.apply_fixes(source, findings)

    assert count == 0
    assert result == source


def test_pattern_based_fix_applies():
    """Test that pattern-based fix applies correctly."""
    source = 'password = "secret123"'
    finding = Finding(
        rule_id="SEC001",
        rule_name="hardcoded-password",
        severity=Severity.HIGH,
        message="Hardcoded password",
        file_path="src/config.py",
        line_number=1,
        column=0,
        code_snippet='password = "secret123"',
        fix_suggestion="",
        education="",
    )
    rule = Rule(
        id="SEC001",
        name="hardcoded-password",
        severity=Severity.HIGH,
        category="security",
        languages=["python"],
        description="Detect hardcoded passwords",
        message="Hardcoded password found",
        pattern={"type": "regex", "value": r'password\s*=\s*"[^"]*"'},
        fix=FixConfig(
            pattern='{var} = {string}',
            replacement='{var} = os.environ.get("{var}")',
        ),
    )

    engine = FixEngine()
    result = engine.apply_fix(source, finding, rule)

    assert result.applied is True
    assert result.reason == "success"
    assert result.original == 'password = "secret123"'
    assert result.fixed == 'password = os.environ.get("password")'


def test_pattern_based_fix_falls_back_to_template():
    """Test that fix falls back to template when pattern doesn't match."""
    source = "some_other_code()"
    finding = Finding(
        rule_id="SEC001",
        rule_name="hardcoded-password",
        severity=Severity.HIGH,
        message="Hardcoded password",
        file_path="src/config.py",
        line_number=1,
        column=0,
        code_snippet="some_other_code()",
        fix_suggestion="",
        education="",
    )
    rule = Rule(
        id="SEC001",
        name="hardcoded-password",
        severity=Severity.HIGH,
        category="security",
        languages=["python"],
        description="Detect hardcoded passwords",
        message="Hardcoded password found",
        pattern={"type": "regex", "value": r'password\s*=\s*"[^"]*"'},
        fix=FixConfig(
            pattern='{var} = {string}',  # Won't match
            replacement='{var} = os.environ.get("{var}")',
            template='password = os.environ.get("PASSWORD")',
        ),
    )

    engine = FixEngine()
    result = engine.apply_fix(source, finding, rule)

    assert result.applied is True
    assert result.reason == "success"
    assert result.fixed == 'password = os.environ.get("PASSWORD")'


def test_fix_result_returns_invalid_line():
    """Test that FixResult returns invalid_line for out of bounds."""
    source = "line 1\nline 2"
    finding = Finding(
        rule_id="TEST001",
        rule_name="test",
        severity=Severity.LOW,
        message="Test",
        file_path="test.py",
        line_number=10,  # Out of bounds
        column=0,
        code_snippet="",
        fix_suggestion="fixed",
        education="",
    )

    engine = FixEngine()
    result = engine.apply_fix(source, finding)

    assert result.applied is False
    assert result.reason == "invalid_line"


def test_apply_fixes_with_rules():
    """Test applying multiple fixes with rules."""
    source = """\
password = "secret"
api_key = "abc123"
"""
    findings = [
        Finding(
            rule_id="SEC001",
            rule_name="hardcoded-secret",
            severity=Severity.HIGH,
            message="Hardcoded secret",
            file_path="config.py",
            line_number=1,
            column=0,
            code_snippet='password = "secret"',
            fix_suggestion="",
            education="",
        ),
        Finding(
            rule_id="SEC001",
            rule_name="hardcoded-secret",
            severity=Severity.HIGH,
            message="Hardcoded secret",
            file_path="config.py",
            line_number=2,
            column=0,
            code_snippet='api_key = "abc123"',
            fix_suggestion="",
            education="",
        ),
    ]
    rules = {
        "SEC001": Rule(
            id="SEC001",
            name="hardcoded-secret",
            severity=Severity.HIGH,
            category="security",
            languages=["python"],
            description="Detect hardcoded secrets",
            message="Hardcoded secret found",
            pattern={"type": "regex", "value": r'\w+\s*=\s*"[^"]*"'},
            fix=FixConfig(
                pattern='{var} = {string}',
                replacement='{var} = os.environ.get("{var}")',
            ),
        ),
    }

    engine = FixEngine()
    result, count = engine.apply_fixes(source, findings, rules)

    assert count == 2
    assert 'password = os.environ.get("password")' in result
    assert 'api_key = os.environ.get("api_key")' in result
