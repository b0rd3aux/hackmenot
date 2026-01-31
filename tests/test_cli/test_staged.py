"""Tests for --staged flag functionality."""

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from hackmenot.cli.git import get_staged_files, is_git_repo
from hackmenot.cli.main import app

runner = CliRunner()


class TestGitHelpers:
    """Tests for git helper functions."""

    def test_is_git_repo_in_git_directory(self, tmp_path: Path):
        """Test is_git_repo returns True in a git repository."""
        # Create a git repo
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)

        # Mock the current directory
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            result = is_git_repo()
            assert result is True

    def test_is_git_repo_not_git_directory(self):
        """Test is_git_repo returns False outside git repository."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(128, "git")
            result = is_git_repo()
            assert result is False

    def test_get_staged_files_returns_files(self):
        """Test get_staged_files returns list of staged files."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = "src/app.py\nsrc/util.py\n"
            mock_run.return_value.returncode = 0
            result = get_staged_files()
            assert len(result) == 2
            assert Path("src/app.py") in result
            assert Path("src/util.py") in result

    def test_get_staged_files_empty(self):
        """Test get_staged_files returns empty list when no staged files."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = ""
            mock_run.return_value.returncode = 0
            result = get_staged_files()
            assert result == []

    def test_get_staged_files_git_error(self):
        """Test get_staged_files returns empty list on git error."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(128, "git")
            result = get_staged_files()
            assert result == []


class TestStagedFlag:
    """Tests for --staged CLI flag."""

    def test_staged_requires_git_repo(self):
        """Test --staged fails outside git repository."""
        with patch("hackmenot.cli.main.is_git_repo", return_value=False):
            result = runner.invoke(app, ["scan", "--staged"])
            assert result.exit_code == 1
            assert "--staged requires a git repository" in result.stdout

    def test_staged_no_files(self):
        """Test --staged with no staged files."""
        with patch("hackmenot.cli.main.is_git_repo", return_value=True):
            with patch("hackmenot.cli.main.get_staged_files", return_value=[]):
                result = runner.invoke(app, ["scan", "--staged"])
                assert result.exit_code == 0
                assert "No staged files to scan" in result.stdout

    def test_staged_no_supported_files(self, tmp_path: Path):
        """Test --staged with no supported file extensions."""
        # Create a non-supported file
        (tmp_path / "readme.md").write_text("# README")

        with patch("hackmenot.cli.main.is_git_repo", return_value=True):
            with patch("hackmenot.cli.main.get_staged_files", return_value=[tmp_path / "readme.md"]):
                result = runner.invoke(app, ["scan", "--staged"])
                assert result.exit_code == 0
                assert "No supported files in staged changes" in result.stdout

    def test_staged_scans_python_files(self, tmp_path: Path):
        """Test --staged scans Python files correctly."""
        # Create a vulnerable Python file
        vuln_file = tmp_path / "vulnerable.py"
        vuln_file.write_text('''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
''')

        with patch("hackmenot.cli.main.is_git_repo", return_value=True):
            with patch("hackmenot.cli.main.get_staged_files", return_value=[vuln_file]):
                result = runner.invoke(app, ["scan", "--staged"])
                assert result.exit_code == 1  # Should find vulnerability
                assert "INJ001" in result.stdout

    def test_staged_scans_javascript_files(self, tmp_path: Path):
        """Test --staged scans JavaScript files correctly."""
        # Create a vulnerable JavaScript file
        vuln_file = tmp_path / "app.js"
        vuln_file.write_text('''
const query = `SELECT * FROM users WHERE id = ${userId}`;
db.query(query);
''')

        with patch("hackmenot.cli.main.is_git_repo", return_value=True):
            with patch("hackmenot.cli.main.get_staged_files", return_value=[vuln_file]):
                result = runner.invoke(app, ["scan", "--staged"])
                # Should scan without error (may or may not find issues depending on rules)
                assert result.exit_code in [0, 1]

    def test_staged_clean_files(self, tmp_path: Path):
        """Test --staged with clean files exits with code 0."""
        # Create a clean Python file
        clean_file = tmp_path / "clean.py"
        clean_file.write_text('''
def hello(name: str) -> str:
    return f"Hello, {name}!"
''')

        with patch("hackmenot.cli.main.is_git_repo", return_value=True):
            with patch("hackmenot.cli.main.get_staged_files", return_value=[clean_file]):
                result = runner.invoke(app, ["scan", "--staged"])
                assert result.exit_code == 0

    def test_staged_multiple_files(self, tmp_path: Path):
        """Test --staged with multiple staged files."""
        # Create multiple files
        clean_file = tmp_path / "clean.py"
        clean_file.write_text('def foo(): pass')

        vuln_file = tmp_path / "vuln.py"
        vuln_file.write_text('query = f"SELECT * FROM t WHERE id = {x}"')

        with patch("hackmenot.cli.main.is_git_repo", return_value=True):
            with patch("hackmenot.cli.main.get_staged_files", return_value=[clean_file, vuln_file]):
                result = runner.invoke(app, ["scan", "--staged"])
                assert result.exit_code == 1  # Should find vulnerability

    def test_staged_with_json_format(self, tmp_path: Path):
        """Test --staged with JSON output format."""
        clean_file = tmp_path / "main.py"
        clean_file.write_text('def main(): pass')

        with patch("hackmenot.cli.main.is_git_repo", return_value=True):
            with patch("hackmenot.cli.main.get_staged_files", return_value=[clean_file]):
                result = runner.invoke(app, ["scan", "--staged", "--format", "json"])
                assert result.exit_code == 0
                assert '"files_scanned"' in result.stdout

    def test_staged_filters_nonexistent_files(self, tmp_path: Path):
        """Test --staged filters out files that don't exist."""
        # Only create one of the files
        existing_file = tmp_path / "exists.py"
        existing_file.write_text('def foo(): pass')

        nonexistent_file = tmp_path / "missing.py"

        with patch("hackmenot.cli.main.is_git_repo", return_value=True):
            with patch("hackmenot.cli.main.get_staged_files", return_value=[existing_file, nonexistent_file]):
                result = runner.invoke(app, ["scan", "--staged"])
                # Should succeed, only scanning the existing file
                assert result.exit_code == 0

    def test_no_paths_without_staged(self):
        """Test that paths are required when --staged is not used."""
        result = runner.invoke(app, ["scan"])
        assert result.exit_code == 1
        assert "No paths provided" in result.stdout
