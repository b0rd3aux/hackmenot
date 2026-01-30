"""Tests for terminal reporter."""

from io import StringIO

from rich.console import Console

from hackmenot.core.models import Finding, ScanResult, Severity
from hackmenot.reporters.terminal import TerminalReporter


def test_reporter_renders_header():
    """Test reporter renders header."""
    reporter = TerminalReporter()
    findings = [
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
    ]
    result = ScanResult(files_scanned=10, findings=findings, scan_time_ms=150)

    output = StringIO()
    console = Console(file=output, force_terminal=True, width=80)
    reporter.console = console

    reporter.render(result)
    rendered = output.getvalue()

    assert "hackmenot" in rendered.lower()


def test_reporter_renders_findings():
    """Test reporter renders all findings."""
    reporter = TerminalReporter()
    findings = [
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
    result = ScanResult(files_scanned=10, findings=findings, scan_time_ms=150)

    output = StringIO()
    console = Console(file=output, force_terminal=True, width=80)
    reporter.console = console

    reporter.render(result)
    rendered = output.getvalue()

    assert "INJ001" in rendered
    assert "AUTH001" in rendered
    assert "src/api.py" in rendered


def test_reporter_renders_summary():
    """Test reporter renders summary with counts."""
    reporter = TerminalReporter()
    findings = [
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
    ]
    result = ScanResult(files_scanned=10, findings=findings, scan_time_ms=150)

    output = StringIO()
    console = Console(file=output, force_terminal=True, width=80)
    reporter.console = console

    reporter.render(result)
    rendered = output.getvalue()

    assert "10" in rendered  # files scanned
    assert "Critical" in rendered or "critical" in rendered.lower()


def test_reporter_handles_no_findings():
    """Test reporter handles empty results."""
    reporter = TerminalReporter()
    result = ScanResult(files_scanned=5, findings=[], scan_time_ms=50)

    output = StringIO()
    console = Console(file=output, force_terminal=True, width=80)
    reporter.console = console

    reporter.render(result)
    rendered = output.getvalue()

    assert "No issues found" in rendered or "0" in rendered
