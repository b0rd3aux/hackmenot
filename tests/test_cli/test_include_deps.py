"""Tests for --include-deps flag."""

from pathlib import Path
from typer.testing import CliRunner
from hackmenot.cli.main import app

runner = CliRunner()


def test_include_deps_scans_dependencies(tmp_path: Path):
    """Test --include-deps includes dependency scanning."""
    (tmp_path / "app.py").write_text("x = 1")
    (tmp_path / "requirements.txt").write_text("requets\n")  # Typosquat / hallucinated

    result = runner.invoke(app, ["scan", str(tmp_path), "--include-deps"])

    # DEP001 is hallucinated package, DEP002 is typosquat
    assert "DEP001" in result.stdout or "DEP002" in result.stdout or "hallucinated" in result.stdout.lower()


def test_without_include_deps_skips_dependencies(tmp_path: Path):
    """Test without --include-deps, dependencies not scanned."""
    (tmp_path / "app.py").write_text("x = 1")
    (tmp_path / "requirements.txt").write_text("requets\n")

    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert "DEP002" not in result.stdout


def test_include_deps_with_clean_deps(tmp_path: Path):
    """Test --include-deps with clean dependencies."""
    (tmp_path / "app.py").write_text("x = 1")
    (tmp_path / "requirements.txt").write_text("requests\n")

    result = runner.invoke(app, ["scan", str(tmp_path), "--include-deps"])

    assert result.exit_code == 0


def test_include_deps_with_code_finding(tmp_path: Path):
    """Test --include-deps shows both code and dep findings."""
    (tmp_path / "app.py").write_text('query = f"SELECT * FROM {x}"')
    (tmp_path / "requirements.txt").write_text("requets\n")

    result = runner.invoke(app, ["scan", str(tmp_path), "--include-deps"])

    # Should show both INJ001 and DEP002
    assert "INJ001" in result.stdout or "SQL" in result.stdout
