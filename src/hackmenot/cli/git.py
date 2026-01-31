"""Git helpers for CI integration."""

import subprocess
from pathlib import Path


def get_staged_files() -> list[Path]:
    """Get list of staged files from git.

    Returns files that are:
    - A: Added
    - C: Copied
    - M: Modified
    - R: Renamed

    Returns:
        List of Path objects for staged files.
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            capture_output=True,
            text=True,
            check=True,
        )
        files = [Path(f) for f in result.stdout.strip().split("\n") if f]
        return files
    except subprocess.CalledProcessError:
        return []


def is_git_repo() -> bool:
    """Check if current directory is a git repository.

    Returns:
        True if in a git repository, False otherwise.
    """
    try:
        subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            capture_output=True,
            check=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def get_changed_files(since: str) -> list[Path]:
    """Get list of files changed since a specific commit/ref.

    Args:
        since: A git ref (commit SHA, branch name, tag, etc.)

    Returns:
        List of Path objects for changed files.
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", since, "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        files = [Path(f) for f in result.stdout.strip().split("\n") if f]
        return files
    except subprocess.CalledProcessError:
        return []
