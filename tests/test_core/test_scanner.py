"""Tests for scanner orchestrator."""

from pathlib import Path

from hackmenot.core.models import Severity
from hackmenot.core.scanner import Scanner


def test_scanner_scans_directory(tmp_path: Path):
    """Test scanner can scan a directory."""
    scanner = Scanner()
    # Create test files
    (tmp_path / "good.py").write_text('def hello():\n    return "hi"\n')
    (tmp_path / "bad.py").write_text('query = f"SELECT * FROM users WHERE id = {x}"\n')

    result = scanner.scan([tmp_path])

    assert result.files_scanned >= 2


def test_scanner_finds_vulnerabilities(tmp_path: Path):
    """Test scanner finds vulnerabilities."""
    scanner = Scanner()
    bad_file = tmp_path / "vuln.py"
    bad_file.write_text("""
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
""")

    result = scanner.scan([tmp_path])

    assert result.has_findings
    assert any(f.rule_id == "INJ001" for f in result.findings)


def test_scanner_respects_severity_filter(tmp_path: Path):
    """Test scanner can filter by severity."""
    scanner = Scanner()
    bad_file = tmp_path / "test.py"
    bad_file.write_text('query = f"SELECT * FROM t WHERE x = {y}"\n')

    # Scan with high minimum severity
    result = scanner.scan([tmp_path], min_severity=Severity.CRITICAL)

    # Should still find the critical SQL injection
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


def test_scanner_ignores_non_python_files(tmp_path: Path):
    """Test scanner ignores non-Python files."""
    scanner = Scanner()
    (tmp_path / "readme.md").write_text("# Hello\n")
    (tmp_path / "data.json").write_text('{"key": "value"}\n')
    (tmp_path / "test.py").write_text('print("hello")\n')

    result = scanner.scan([tmp_path])

    # Should only scan the .py file
    assert result.files_scanned == 1


def test_scanner_handles_empty_directory(tmp_path: Path):
    """Test scanner handles empty directory."""
    scanner = Scanner()
    result = scanner.scan([tmp_path])

    assert result.files_scanned == 0
    assert not result.has_findings


class TestSkipDirs:
    """Test SKIP_DIRS filtering during file collection."""

    def test_skips_node_modules(self, tmp_path: Path) -> None:
        """Verify node_modules directories are skipped."""
        # Create structure with node_modules
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.py").write_text('query = f"SELECT * FROM users WHERE id = {x}"')

        node_modules = tmp_path / "node_modules"
        node_modules.mkdir()
        (node_modules / "pkg" / "index.js").parent.mkdir(parents=True)
        (node_modules / "pkg" / "index.js").write_text("const secret = 'key'")

        scanner = Scanner()
        result = scanner.scan([tmp_path])

        # Should find app.py but NOT anything in node_modules
        assert result.files_scanned == 1
        assert any("app.py" in f.file_path for f in result.findings)
        # Use path separator to avoid matching the pytest temp dir name
        assert not any("/node_modules/" in f.file_path for f in result.findings)

    def test_skips_pycache(self, tmp_path: Path) -> None:
        """Verify __pycache__ directories are skipped."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "main.py").write_text("api_key = 'abc123'")

        pycache = tmp_path / "__pycache__"
        pycache.mkdir()
        # Create a .py file that would be scanned if __pycache__ wasn't skipped
        (pycache / "cached_module.py").write_text("secret = 'cached'")

        scanner = Scanner()
        result = scanner.scan([tmp_path])

        # Should scan main.py but not files in __pycache__
        assert result.files_scanned == 1
        assert not any("/__pycache__/" in f.file_path for f in result.findings)

    def test_skips_dotgit(self, tmp_path: Path) -> None:
        """Verify .git directories are skipped."""
        (tmp_path / "app.py").write_text("secret = 'value'")

        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir()
        # Create a .py file that would be scanned if .git wasn't skipped
        (hooks_dir / "pre-commit.py").write_text("password = 'gitpass'")

        scanner = Scanner()
        result = scanner.scan([tmp_path])

        # Should not scan .git
        assert result.files_scanned == 1
        assert not any("/.git/" in f.file_path for f in result.findings)

    def test_skips_venv(self, tmp_path: Path) -> None:
        """Verify venv/virtualenv directories are skipped."""
        (tmp_path / "main.py").write_text("key = 'test'")

        venv = tmp_path / "venv"
        venv.mkdir()
        (venv / "lib" / "site.py").parent.mkdir(parents=True)
        (venv / "lib" / "site.py").write_text("secret = 'venv'")

        scanner = Scanner()
        result = scanner.scan([tmp_path])

        assert result.files_scanned == 1
        # Use path separator to be specific about directory matching
        assert not any("/venv/" in f.file_path for f in result.findings)

    def test_skips_egg_info(self, tmp_path: Path) -> None:
        """Verify .egg-info directories are skipped."""
        (tmp_path / "main.py").write_text("secret = 'value'")

        egg_info = tmp_path / "mypackage.egg-info"
        egg_info.mkdir()
        (egg_info / "PKG-INFO").write_text("password = 'egg'")

        scanner = Scanner()
        result = scanner.scan([tmp_path])

        assert result.files_scanned == 1
        assert not any(".egg-info" in f.file_path for f in result.findings)
