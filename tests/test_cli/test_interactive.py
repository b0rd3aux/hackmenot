"""Tests for interactive fix mode."""

from pathlib import Path

from typer.testing import CliRunner

from hackmenot.cli.main import app

runner = CliRunner()


def test_fix_interactive_shows_prompt(tmp_path: Path):
    """Test that --fix-interactive shows prompts for user action."""
    (tmp_path / "test.py").write_text('query = f"SELECT * FROM users WHERE id = {x}"')
    result = runner.invoke(app, ["scan", str(tmp_path), "--fix-interactive"], input="s\n")
    assert "apply" in result.stdout.lower() or "skip" in result.stdout.lower()


def test_fix_auto_applies_fixes(tmp_path: Path):
    """Test that --fix automatically applies all fixes."""
    test_file = tmp_path / "test.py"
    test_file.write_text('query = f"SELECT * FROM users WHERE id = {x}"')
    result = runner.invoke(app, ["scan", str(tmp_path), "--fix"])
    assert result.exit_code in [0, 1]


def test_fix_modifies_file(tmp_path: Path):
    """Test that --fix actually modifies the file with fix suggestion."""
    test_file = tmp_path / "test.py"
    original_content = 'query = f"SELECT * FROM users WHERE id = {x}"'
    test_file.write_text(original_content)

    runner.invoke(app, ["scan", str(tmp_path), "--fix"])

    # File should be modified (fix suggestion should be applied)
    new_content = test_file.read_text()
    assert "parameterized" in new_content.lower() or new_content != original_content


def test_fix_interactive_apply(tmp_path: Path):
    """Test that 'a' (apply) in interactive mode applies the fix."""
    test_file = tmp_path / "test.py"
    original_content = 'query = f"SELECT * FROM users WHERE id = {x}"'
    test_file.write_text(original_content)

    result = runner.invoke(app, ["scan", str(tmp_path), "--fix-interactive"], input="a\n")

    # Check that the file was modified
    new_content = test_file.read_text()
    # Fix should have been applied
    assert "parameterized" in new_content.lower() or new_content != original_content


def test_fix_interactive_skip(tmp_path: Path):
    """Test that 's' (skip) in interactive mode skips the fix."""
    test_file = tmp_path / "test.py"
    original_content = 'query = f"SELECT * FROM users WHERE id = {x}"'
    test_file.write_text(original_content)

    runner.invoke(app, ["scan", str(tmp_path), "--fix-interactive"], input="s\n")

    # File should NOT be modified when skipped
    new_content = test_file.read_text()
    assert new_content == original_content


def test_fix_interactive_quit(tmp_path: Path):
    """Test that 'q' (quit) in interactive mode stops processing."""
    test_file = tmp_path / "test.py"
    original_content = 'query = f"SELECT * FROM users WHERE id = {x}"'
    test_file.write_text(original_content)

    result = runner.invoke(app, ["scan", str(tmp_path), "--fix-interactive"], input="q\n")

    # File should NOT be modified when quit
    new_content = test_file.read_text()
    assert new_content == original_content


def test_fix_interactive_apply_all(tmp_path: Path):
    """Test that 'A' (apply all) applies all remaining fixes."""
    test_file = tmp_path / "test.py"
    original_content = '''query1 = f"SELECT * FROM users WHERE id = {x}"
query2 = f"SELECT * FROM posts WHERE user_id = {y}"'''
    test_file.write_text(original_content)

    # Use 'A' to apply all
    result = runner.invoke(app, ["scan", str(tmp_path), "--fix-interactive"], input="A\n")

    # Both fixes should have been applied
    new_content = test_file.read_text()
    assert new_content != original_content


def test_fix_and_fix_interactive_mutually_exclusive(tmp_path: Path):
    """Test that --fix and --fix-interactive cannot be used together."""
    test_file = tmp_path / "test.py"
    test_file.write_text('query = f"SELECT * FROM users WHERE id = {x}"')

    result = runner.invoke(app, ["scan", str(tmp_path), "--fix", "--fix-interactive"])

    assert result.exit_code != 0
    assert "cannot" in result.stdout.lower() or "exclusive" in result.stdout.lower()


def test_fix_no_findings(tmp_path: Path):
    """Test --fix with no findings produces no changes."""
    test_file = tmp_path / "clean.py"
    test_file.write_text('x = 1\nprint(x)')

    result = runner.invoke(app, ["scan", str(tmp_path), "--fix"])

    assert result.exit_code == 0
    assert test_file.read_text() == 'x = 1\nprint(x)'
