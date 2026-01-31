"""Tests for CI-friendly output flag."""

from pathlib import Path

from typer.testing import CliRunner

from hackmenot.cli.main import app

runner = CliRunner()


def test_ci_flag_disables_colors(tmp_path: Path):
    """Test --ci removes ANSI escape codes."""
    (tmp_path / "test.py").write_text('x = 1')
    result = runner.invoke(app, ["scan", str(tmp_path), "--ci"])
    # Check no ANSI escape codes in output
    assert "\x1b[" not in result.stdout


def test_ci_exit_code_zero_clean(tmp_path: Path):
    """Test exit code 0 for clean scan."""
    (tmp_path / "test.py").write_text('x = 1')
    result = runner.invoke(app, ["scan", str(tmp_path), "--ci"])
    assert result.exit_code == 0


def test_ci_exit_code_one_findings(tmp_path: Path):
    """Test exit code 1 for findings."""
    (tmp_path / "test.py").write_text('query = f"SELECT * FROM {x}"')
    result = runner.invoke(app, ["scan", str(tmp_path), "--ci"])
    assert result.exit_code == 1


def test_ci_flag_in_help():
    """Test --ci flag is listed in help."""
    result = runner.invoke(app, ["scan", "--help"])
    assert "--ci" in result.stdout
    assert "CI-friendly" in result.stdout


def test_ci_no_colors_with_findings(tmp_path: Path):
    """Test --ci has no colors even with findings."""
    (tmp_path / "test.py").write_text('query = f"SELECT * FROM {x}"')
    result = runner.invoke(app, ["scan", str(tmp_path), "--ci"])
    # Check no ANSI escape codes in output
    assert "\x1b[" not in result.stdout
    # Should still report the finding
    assert "INJ001" in result.stdout or "SQL" in result.stdout.lower()
