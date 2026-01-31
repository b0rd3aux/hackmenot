"""Tests for git helper functions - changed files since commit."""

import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from hackmenot.cli.main import app

runner = CliRunner()


def test_get_changed_files_since_commit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test getting files changed since a specific commit."""
    # Create a git repo with some history
    monkeypatch.chdir(tmp_path)
    subprocess.run(["git", "init"], capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], capture_output=True, check=True)

    # Create initial commit
    (tmp_path / "initial.py").write_text("# initial")
    subprocess.run(["git", "add", "initial.py"], capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "initial"], capture_output=True, check=True)

    # Get the commit SHA
    result = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
    initial_sha = result.stdout.strip()

    # Create more changes
    (tmp_path / "changed.py").write_text("# changed")
    subprocess.run(["git", "add", "changed.py"], capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "add changed"], capture_output=True, check=True)

    # Get changed files since initial commit
    from hackmenot.cli.git import get_changed_files
    changed = get_changed_files(initial_sha)

    assert len(changed) == 1
    assert changed[0].name == "changed.py"


def test_get_changed_files_invalid_ref() -> None:
    """Test that invalid ref returns empty list."""
    from hackmenot.cli.git import get_changed_files
    changed = get_changed_files("nonexistent-ref-abc123")
    assert changed == []


def test_scan_changed_since_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test --changed-since CLI flag."""
    monkeypatch.chdir(tmp_path)

    # Create git repo
    subprocess.run(["git", "init"], capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], capture_output=True, check=True)

    # Initial commit
    (tmp_path / "initial.py").write_text("# safe")
    subprocess.run(["git", "add", "."], capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "initial"], capture_output=True, check=True)

    result = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
    initial_sha = result.stdout.strip()

    # Add file with vulnerability (SQL injection)
    (tmp_path / "vuln.py").write_text('query = f"SELECT * FROM users WHERE id = {user_id}"')
    subprocess.run(["git", "add", "."], capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "add vuln"], capture_output=True, check=True)

    # Scan only changes since initial commit
    result = runner.invoke(app, ["scan", "--changed-since", initial_sha, "--format", "json"])

    assert result.exit_code == 1  # Should find vulnerability
    assert "vuln.py" in result.stdout


def test_scan_changed_since_requires_git_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test --changed-since requires a git repository."""
    from unittest.mock import patch

    with patch("hackmenot.cli.main.is_git_repo", return_value=False):
        result = runner.invoke(app, ["scan", "--changed-since", "abc123"])
        assert result.exit_code == 1
        assert "--changed-since requires a git repository" in result.stdout


def test_scan_changed_since_no_changes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test --changed-since with no changed files."""
    monkeypatch.chdir(tmp_path)

    # Create git repo
    subprocess.run(["git", "init"], capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], capture_output=True, check=True)

    # Create and commit a file
    (tmp_path / "test.py").write_text("# test")
    subprocess.run(["git", "add", "."], capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "initial"], capture_output=True, check=True)

    result = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
    latest_sha = result.stdout.strip()

    # Scan since the latest commit (no changes)
    result = runner.invoke(app, ["scan", "--changed-since", latest_sha])
    assert result.exit_code == 0
    assert f"No files changed since {latest_sha}" in result.stdout


def test_scan_changed_since_no_supported_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test --changed-since with changes but no supported file types."""
    monkeypatch.chdir(tmp_path)

    # Create git repo
    subprocess.run(["git", "init"], capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], capture_output=True, check=True)

    # Initial commit
    (tmp_path / "initial.py").write_text("# initial")
    subprocess.run(["git", "add", "."], capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "initial"], capture_output=True, check=True)

    result = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
    initial_sha = result.stdout.strip()

    # Add a file with unsupported extension
    (tmp_path / "readme.md").write_text("# README")
    subprocess.run(["git", "add", "."], capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "add readme"], capture_output=True, check=True)

    # Scan since initial commit
    result = runner.invoke(app, ["scan", "--changed-since", initial_sha])
    assert result.exit_code == 0
    assert "No supported files in changes" in result.stdout


def test_staged_and_changed_since_mutually_exclusive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that --staged and --changed-since cannot be used together."""
    from typer.testing import CliRunner
    from hackmenot.cli.main import app

    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    # Create a minimal git repo
    subprocess.run(["git", "init"], capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], capture_output=True, check=True)

    result = runner.invoke(app, ["scan", "--staged", "--changed-since", "HEAD"])

    assert result.exit_code == 1
    assert "cannot be used together" in result.stdout
