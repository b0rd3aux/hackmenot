"""Tests for CLI flags (--full and --config)."""

from pathlib import Path

from typer.testing import CliRunner

from hackmenot.cli.main import app

runner = CliRunner()


def test_full_flag_bypasses_cache(tmp_path: Path):
    """Test that --full flag is accepted and bypasses cache."""
    (tmp_path / "test.py").write_text("x = 1")
    result = runner.invoke(app, ["scan", str(tmp_path), "--full"])
    assert result.exit_code == 0


def test_config_flag_loads_config(tmp_path: Path):
    """Test that --config flag loads custom config file."""
    config_file = tmp_path / "custom.yml"
    config_file.write_text("fail_on: low")
    (tmp_path / "test.py").write_text("x = 1")
    result = runner.invoke(app, ["scan", str(tmp_path), "--config", str(config_file)])
    assert result.exit_code == 0


def test_config_short_flag(tmp_path: Path):
    """Test that -c short flag works for config."""
    config_file = tmp_path / "custom.yml"
    config_file.write_text("fail_on: low")
    (tmp_path / "test.py").write_text("x = 1")
    result = runner.invoke(app, ["scan", str(tmp_path), "-c", str(config_file)])
    assert result.exit_code == 0


def test_full_and_config_together(tmp_path: Path):
    """Test that --full and --config can be used together."""
    config_file = tmp_path / "custom.yml"
    config_file.write_text("fail_on: low")
    (tmp_path / "test.py").write_text("x = 1")
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--full", "--config", str(config_file)]
    )
    assert result.exit_code == 0


def test_config_file_not_found(tmp_path: Path):
    """Test that non-existent config file shows error."""
    (tmp_path / "test.py").write_text("x = 1")
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--config", str(tmp_path / "nonexistent.yml")]
    )
    assert result.exit_code == 1
    assert "Config file not found" in result.stdout or "not found" in result.stdout.lower()
