"""Tests for scanner orchestrator."""

from pathlib import Path

from hackmenot.core.models import Severity
from hackmenot.core.scanner import Scanner


def test_scanner_scans_directory(tmp_path: Path):
    """Test scanner can scan a directory."""
    scanner = Scanner()
    # Create test files
    (tmp_path / "good.py").write_text('def hello():\n    return "hi"\n')
    (tmp_path / "bad.py").write_text('query = f"SELECT * FROM users WHERE id = {x}"\n')

    result = scanner.scan([tmp_path])

    assert result.files_scanned >= 2


def test_scanner_finds_vulnerabilities(tmp_path: Path):
    """Test scanner finds vulnerabilities."""
    scanner = Scanner()
    bad_file = tmp_path / "vuln.py"
    bad_file.write_text("""
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
""")

    result = scanner.scan([tmp_path])

    assert result.has_findings
    assert any(f.rule_id == "INJ001" for f in result.findings)


def test_scanner_respects_severity_filter(tmp_path: Path):
    """Test scanner can filter by severity."""
    scanner = Scanner()
    bad_file = tmp_path / "test.py"
    bad_file.write_text('query = f"SELECT * FROM t WHERE x = {y}"\n')

    # Scan with high minimum severity
    result = scanner.scan([tmp_path], min_severity=Severity.CRITICAL)

    # Should still find the critical SQL injection
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


def test_scanner_ignores_non_python_files(tmp_path: Path):
    """Test scanner ignores non-Python files."""
    scanner = Scanner()
    (tmp_path / "readme.md").write_text("# Hello\n")
    (tmp_path / "data.json").write_text('{"key": "value"}\n')
    (tmp_path / "test.py").write_text('print("hello")\n')

    result = scanner.scan([tmp_path])

    # Should only scan the .py file
    assert result.files_scanned == 1


def test_scanner_handles_empty_directory(tmp_path: Path):
    """Test scanner handles empty directory."""
    scanner = Scanner()
    result = scanner.scan([tmp_path])

    assert result.files_scanned == 0
    assert not result.has_findings
