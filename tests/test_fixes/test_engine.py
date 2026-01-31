"""Tests for FixEngine."""

from hackmenot.core.models import Finding, Severity
from hackmenot.fixes.engine import FixEngine


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

    assert result is not None
    assert "@login_required" in result
    assert "def get_user():" in result
    assert "return db.query(User)" in result


def test_fix_engine_returns_none_when_no_fix():
    """Test that FixEngine returns None if no fix_suggestion."""
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

    assert result is None


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

    assert result is not None
    lines = result.split("\n")
    assert lines[0] == "import os"
    assert lines[1] == ""
    assert "@login_required" in result
    assert "def delete_user():" in result


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

    assert result is not None
    lines = result.split("\n")
    # The decorator and function should be indented
    assert "    @login_required" in result
    assert "    def get_user(self):" in result


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
