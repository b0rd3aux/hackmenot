"""Integration tests for end-to-end scanning."""

import json
from pathlib import Path

from typer.testing import CliRunner

from hackmenot.cli.main import app

runner = CliRunner()


def _create_sample_project(tmp_path: Path) -> Path:
    """Create a realistic sample project."""
    # Create directory structure
    src = tmp_path / "src"
    src.mkdir()

    # Good file
    (src / "utils.py").write_text('''
"""Utility functions."""

def format_name(first: str, last: str) -> str:
    """Format a full name."""
    return f"{first} {last}"
''')

    # File with SQL injection
    (src / "database.py").write_text('''
"""Database operations."""

def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return execute(query)

def get_all_users():
    return execute("SELECT * FROM users")
''')

    # File with missing auth
    (src / "api.py").write_text('''
"""API endpoints."""
from flask import Flask
app = Flask(__name__)

@app.route("/users")
def list_users():
    return get_all_users()

@app.route("/health")
def health():
    return "ok"
''')

    return tmp_path


def test_full_scan_workflow(tmp_path: Path):
    """Test complete scan workflow."""
    sample_project = _create_sample_project(tmp_path)
    result = runner.invoke(app, ["scan", str(sample_project)])

    # Should find issues
    assert result.exit_code == 1

    # Should report SQL injection
    assert "INJ001" in result.stdout

    # Should report missing auth
    assert "AUTH001" in result.stdout

    # Should show summary
    assert "Critical" in result.stdout or "critical" in result.stdout.lower()


def test_scan_specific_file(tmp_path: Path):
    """Test scanning a specific file."""
    sample_project = _create_sample_project(tmp_path)
    result = runner.invoke(app, [
        "scan",
        str(sample_project / "src" / "utils.py")
    ])

    # Clean file should pass
    assert result.exit_code == 0


def test_json_output_valid(tmp_path: Path):
    """Test JSON output is valid."""
    sample_project = _create_sample_project(tmp_path)
    result = runner.invoke(app, [
        "scan",
        str(sample_project),
        "--format", "json"
    ])

    # Should be valid JSON
    data = json.loads(result.stdout)
    assert "files_scanned" in data
    assert "findings" in data
    assert isinstance(data["findings"], list)


def test_severity_filtering(tmp_path: Path):
    """Test severity filtering works."""
    sample_project = _create_sample_project(tmp_path)
    # With high severity filter, should still find critical SQL injection
    result = runner.invoke(app, [
        "scan",
        str(sample_project),
        "--severity", "high"
    ])

    assert result.exit_code == 1
    assert "INJ001" in result.stdout


def test_rules_command():
    """Test rules listing command."""
    result = runner.invoke(app, ["rules"])

    assert result.exit_code == 0
    assert "INJ001" in result.stdout
    assert "AUTH001" in result.stdout


def test_rules_show_specific():
    """Test showing specific rule."""
    result = runner.invoke(app, ["rules", "INJ001"])

    assert result.exit_code == 0
    assert "SQL" in result.stdout or "injection" in result.stdout.lower()
