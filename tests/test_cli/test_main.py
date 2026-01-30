"""Tests for CLI main entry point."""

from typer.testing import CliRunner

from hackmenot.cli.main import app

runner = CliRunner()


def test_version_flag():
    """Test --version flag shows version."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.stdout


def test_scan_command_exists():
    """Test scan command is available."""
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "Scan" in result.stdout or "scan" in result.stdout.lower()
