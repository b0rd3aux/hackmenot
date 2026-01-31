"""Tests for --dry-run and --diff CLI flags."""

from pathlib import Path

from typer.testing import CliRunner

from hackmenot.cli.main import app

runner = CliRunner()


class TestDryRunFlag:
    """Tests for --dry-run flag."""

    def test_dry_run_requires_fix_flag(self, tmp_path: Path):
        """Test that --dry-run requires --fix."""
        (tmp_path / "test.py").write_text("x = 1")
        result = runner.invoke(app, ["scan", str(tmp_path), "--dry-run"])
        assert result.exit_code == 1
        assert "--dry-run requires --fix" in result.stdout

    def test_dry_run_shows_summary(self, tmp_path: Path):
        """Test that --dry-run shows fix summary without applying."""
        # Create vulnerable file (SQL injection triggers INJ001)
        vuln_file = tmp_path / "vuln.py"
        original_content = '''def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
'''
        vuln_file.write_text(original_content)

        result = runner.invoke(app, ["scan", str(tmp_path), "--fix", "--dry-run"])

        # Should not have modified the file
        assert vuln_file.read_text() == original_content
        # Exit code 1 indicates findings were found
        assert result.exit_code == 1

    def test_dry_run_does_not_modify_files(self, tmp_path: Path):
        """Test that --dry-run does not write any files."""
        # Create vulnerable file (SQL injection)
        original_content = '''def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
'''
        vuln_file = tmp_path / "vuln.py"
        vuln_file.write_text(original_content)

        runner.invoke(app, ["scan", str(tmp_path), "--fix", "--dry-run"])

        # File should be unchanged
        assert vuln_file.read_text() == original_content

    def test_dry_run_with_clean_code(self, tmp_path: Path):
        """Test --dry-run on clean code shows no fixes."""
        (tmp_path / "clean.py").write_text("def hello():\n    return 'world'\n")
        result = runner.invoke(app, ["scan", str(tmp_path), "--fix", "--dry-run"])
        assert result.exit_code == 0


class TestDiffFlag:
    """Tests for --diff flag."""

    def test_diff_requires_dry_run(self, tmp_path: Path):
        """Test that --diff requires --dry-run."""
        (tmp_path / "test.py").write_text("x = 1")
        result = runner.invoke(app, ["scan", str(tmp_path), "--fix", "--diff"])
        assert result.exit_code == 1
        assert "--diff requires --dry-run" in result.stdout

    def test_diff_shows_unified_diff(self, tmp_path: Path):
        """Test that --diff shows unified diff output."""
        # Create vulnerable file (SQL injection)
        vuln_file = tmp_path / "vuln.py"
        vuln_file.write_text('''def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
''')

        result = runner.invoke(
            app, ["scan", str(tmp_path), "--fix", "--dry-run", "--diff"]
        )

        # Exit code 1 indicates findings were found
        assert result.exit_code == 1

    def test_diff_without_fix_flag_fails(self, tmp_path: Path):
        """Test that --diff without --fix fails."""
        (tmp_path / "test.py").write_text("x = 1")
        result = runner.invoke(app, ["scan", str(tmp_path), "--diff"])
        assert result.exit_code == 1
        assert "--diff requires --dry-run" in result.stdout


class TestFixFlagsCombinations:
    """Tests for various fix flag combinations."""

    def test_fix_without_dry_run_applies_changes(self, tmp_path: Path):
        """Test that --fix without --dry-run applies changes."""
        # This is existing behavior we want to preserve
        (tmp_path / "clean.py").write_text("def hello():\n    return 'world'\n")
        result = runner.invoke(app, ["scan", str(tmp_path), "--fix"])
        assert result.exit_code == 0

    def test_fix_interactive_incompatible_with_dry_run(self, tmp_path: Path):
        """Test that --fix-interactive and --dry-run together."""
        # --dry-run requires --fix, and --fix is mutually exclusive with --fix-interactive
        (tmp_path / "test.py").write_text("x = 1")
        result = runner.invoke(
            app, ["scan", str(tmp_path), "--fix-interactive", "--dry-run"]
        )
        assert result.exit_code == 1
        assert "--dry-run requires --fix" in result.stdout

    def test_all_fix_flags_together_fails(self, tmp_path: Path):
        """Test that --fix and --fix-interactive together fails."""
        (tmp_path / "test.py").write_text("x = 1")
        result = runner.invoke(
            app, ["scan", str(tmp_path), "--fix", "--fix-interactive"]
        )
        assert result.exit_code == 1
        assert "cannot be used together" in result.stdout
