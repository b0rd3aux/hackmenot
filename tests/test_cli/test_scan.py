"""Tests for scan command."""

from pathlib import Path

from typer.testing import CliRunner

from hackmenot.cli.main import app

runner = CliRunner()


def test_scan_finds_vulnerabilities(tmp_path: Path):
    """Test scan command finds vulnerabilities."""
    (tmp_path / "api.py").write_text('''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
''')
    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == 1  # Non-zero for findings
    assert "INJ001" in result.stdout


def test_scan_clean_project_succeeds(tmp_path: Path):
    """Test scan command succeeds on clean code."""
    (tmp_path / "main.py").write_text('''
def hello(name: str) -> str:
    return f"Hello, {name}!"
''')
    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == 0


def test_scan_json_output(tmp_path: Path):
    """Test scan with JSON output format."""
    (tmp_path / "api.py").write_text('''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
''')
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])

    assert result.exit_code == 1
    assert '"rule_id"' in result.stdout or "INJ001" in result.stdout


def test_scan_with_severity_filter(tmp_path: Path):
    """Test scan with severity filter."""
    (tmp_path / "api.py").write_text('''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
''')
    result = runner.invoke(app, [
        "scan", str(tmp_path),
        "--severity", "critical"
    ])

    # Should still exit non-zero since INJ001 is critical
    assert result.exit_code == 1
