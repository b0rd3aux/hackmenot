"""Tests for inline ignore integration in the scanner."""

from pathlib import Path

from hackmenot.core.scanner import Scanner


def test_scanner_respects_inline_ignores(tmp_path: Path):
    """Test that scanner respects inline ignore-next-line comments."""
    scanner = Scanner()
    (tmp_path / "test.py").write_text('''
# hackmenot:ignore-next-line[INJ001] - test fixture
query = f"SELECT * FROM users WHERE id = {x}"
''')
    result = scanner.scan([tmp_path])
    assert not any(f.rule_id == "INJ001" for f in result.findings)


def test_scanner_respects_file_ignore(tmp_path: Path):
    """Test that scanner respects file-level ignore comments."""
    scanner = Scanner()
    (tmp_path / "test.py").write_text('''# hackmenot:ignore-file - generated code
query = f"SELECT * FROM users WHERE id = {x}"
password = "secret"
''')
    result = scanner.scan([tmp_path])
    assert len(result.findings) == 0


def test_scanner_respects_same_line_ignore(tmp_path: Path):
    """Test that scanner respects same-line ignore comments."""
    scanner = Scanner()
    (tmp_path / "test.py").write_text('''
query = f"SELECT * FROM users WHERE id = {x}"  # hackmenot:ignore[INJ001] - known safe
''')
    result = scanner.scan([tmp_path])
    assert not any(f.rule_id == "INJ001" for f in result.findings)


def test_scanner_does_not_ignore_without_reason(tmp_path: Path):
    """Test that scanner does not ignore findings when reason is missing."""
    scanner = Scanner()
    # Note: no reason after the dash - this should NOT suppress the finding
    (tmp_path / "test.py").write_text('''
# hackmenot:ignore-next-line[INJ001]
query = f"SELECT * FROM users WHERE id = {x}"
''')
    result = scanner.scan([tmp_path])
    # The finding should still appear because the ignore is invalid (no reason)
    assert any(f.rule_id == "INJ001" for f in result.findings)


def test_scanner_ignores_only_specified_rule(tmp_path: Path):
    """Test that scanner only ignores the specified rule, not all rules."""
    scanner = Scanner()
    (tmp_path / "test.py").write_text('''
# hackmenot:ignore-next-line[OTHER001] - wrong rule
query = f"SELECT * FROM users WHERE id = {x}"
''')
    result = scanner.scan([tmp_path])
    # INJ001 should still be reported because we only ignored OTHER001
    assert any(f.rule_id == "INJ001" for f in result.findings)


def test_scanner_without_ignores_reports_findings(tmp_path: Path):
    """Test that scanner reports findings when no ignore comments are present."""
    scanner = Scanner()
    (tmp_path / "test.py").write_text('''
query = f"SELECT * FROM users WHERE id = {x}"
''')
    result = scanner.scan([tmp_path])
    assert any(f.rule_id == "INJ001" for f in result.findings)
