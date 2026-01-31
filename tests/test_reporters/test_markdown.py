"""Tests for Markdown reporter."""

from hackmenot import __version__
from hackmenot.core.models import Finding, ScanResult, Severity
from hackmenot.reporters.markdown import MarkdownReporter


def test_markdown_no_findings():
    """Test markdown output when no findings."""
    reporter = MarkdownReporter()
    result = ScanResult(files_scanned=5, findings=[], scan_time_ms=50)

    output = reporter.render(result)

    assert "## 🔒 hackmenot Security Scan" in output
    assert "✅ **No security issues found!**" in output
    assert f"v{__version__}" in output


def test_markdown_with_findings():
    """Test markdown output with findings."""
    reporter = MarkdownReporter()
    findings = [
        Finding(
            rule_id="INJ001",
            rule_name="sql-injection",
            severity=Severity.CRITICAL,
            message="SQL injection detected",
            file_path="src/api.py",
            line_number=42,
            column=5,
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
    result = ScanResult(files_scanned=10, findings=findings, scan_time_ms=150)

    output = reporter.render(result)

    assert "## 🔒 hackmenot Security Scan" in output
    assert "**Found 2 issues**" in output
    assert "10 files scanned" in output
    assert "### Findings" in output
    assert "INJ001" in output
    assert "AUTH001" in output
    assert "src/api.py:42" in output
    assert "src/api.py:50" in output


def test_markdown_severity_table():
    """Test severity summary table."""
    reporter = MarkdownReporter()
    findings = [
        Finding(
            rule_id="TEST001",
            rule_name="test-critical",
            severity=Severity.CRITICAL,
            message="Critical finding",
            file_path="test.py",
            line_number=1,
            column=0,
            code_snippet="code",
            fix_suggestion="",
            education="",
        ),
        Finding(
            rule_id="TEST002",
            rule_name="test-high",
            severity=Severity.HIGH,
            message="High finding",
            file_path="test.py",
            line_number=2,
            column=0,
            code_snippet="code",
            fix_suggestion="",
            education="",
        ),
        Finding(
            rule_id="TEST003",
            rule_name="test-medium",
            severity=Severity.MEDIUM,
            message="Medium finding",
            file_path="test.py",
            line_number=3,
            column=0,
            code_snippet="code",
            fix_suggestion="",
            education="",
        ),
    ]
    result = ScanResult(files_scanned=1, findings=findings, scan_time_ms=10)

    output = reporter.render(result)

    # Check table structure
    assert "| Severity | Count |" in output
    assert "|----------|-------|" in output
    # Check severity emoji mappings
    assert "🔴 Critical | 1 |" in output
    assert "🟠 High | 1 |" in output
    assert "🟡 Medium | 1 |" in output
    assert "🟢 Low | 0 |" in output


def test_markdown_truncates_findings():
    """Test that findings list is truncated to 10 items."""
    reporter = MarkdownReporter()
    findings = [
        Finding(
            rule_id=f"TEST{i:03d}",
            rule_name=f"test-{i}",
            severity=Severity.MEDIUM,
            message=f"Finding {i}",
            file_path="test.py",
            line_number=i,
            column=0,
            code_snippet="code",
            fix_suggestion="",
            education="",
        )
        for i in range(15)
    ]
    result = ScanResult(files_scanned=1, findings=findings, scan_time_ms=10)

    output = reporter.render(result)

    # Should show first 10 findings
    assert "TEST000" in output
    assert "TEST009" in output
    # Should not show findings beyond 10
    assert "TEST010" not in output
    assert "TEST014" not in output
    # Should show truncation message
    assert "... and 5 more" in output


def test_markdown_severity_emojis():
    """Test that correct emojis are used for each severity."""
    reporter = MarkdownReporter()
    findings = [
        Finding(
            rule_id="CRIT001",
            rule_name="critical",
            severity=Severity.CRITICAL,
            message="Critical issue",
            file_path="test.py",
            line_number=1,
            column=0,
            code_snippet="code",
            fix_suggestion="",
            education="",
        ),
        Finding(
            rule_id="HIGH001",
            rule_name="high",
            severity=Severity.HIGH,
            message="High issue",
            file_path="test.py",
            line_number=2,
            column=0,
            code_snippet="code",
            fix_suggestion="",
            education="",
        ),
        Finding(
            rule_id="MED001",
            rule_name="medium",
            severity=Severity.MEDIUM,
            message="Medium issue",
            file_path="test.py",
            line_number=3,
            column=0,
            code_snippet="code",
            fix_suggestion="",
            education="",
        ),
        Finding(
            rule_id="LOW001",
            rule_name="low",
            severity=Severity.LOW,
            message="Low issue",
            file_path="test.py",
            line_number=4,
            column=0,
            code_snippet="code",
            fix_suggestion="",
            education="",
        ),
    ]
    result = ScanResult(files_scanned=1, findings=findings, scan_time_ms=10)

    output = reporter.render(result)

    # Check emojis are correctly associated with findings in the findings list
    assert "**🔴 CRIT001**" in output
    assert "**🟠 HIGH001**" in output
    assert "**🟡 MED001**" in output
    assert "**🟢 LOW001**" in output


def test_markdown_contains_footer():
    """Test that markdown contains footer with version."""
    reporter = MarkdownReporter()
    result = ScanResult(files_scanned=5, findings=[], scan_time_ms=50)

    output = reporter.render(result)

    assert "---" in output
    assert "hackmenot](https://github.com/hackmenot/hackmenot)" in output
    assert f"v{__version__}" in output
