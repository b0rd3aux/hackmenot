"""Integration tests for dependency scanning."""

from pathlib import Path

from typer.testing import CliRunner

from hackmenot.cli.main import app
from hackmenot.deps.scanner import DependencyScanner

runner = CliRunner()


class TestDependencyIntegration:
    """End-to-end tests for dependency scanning."""

    def test_full_scan_python_project(self, tmp_path: Path):
        """Test full dependency scan on Python project."""
        (tmp_path / "requirements.txt").write_text(
            "requests==2.31.0\n"
            "flask==2.0.0\n"
            "fake-hallucinated-pkg\n"
            "requets==1.0.0\n"
        )

        result = runner.invoke(app, ["deps", str(tmp_path)])

        # Both are detected as hallucinated (not in registry)
        # Note: typosquat detection only runs if package exists
        assert "DEP001" in result.stdout  # Hallucinated
        assert "fake-hallucinated-pkg" in result.stdout
        assert "requets" in result.stdout

    def test_full_scan_npm_project(self, tmp_path: Path):
        """Test full dependency scan on npm project."""
        (tmp_path / "package.json").write_text(
            '{"dependencies": {"lodash": "4.17.0", "lodashe": "1.0.0"}}'
        )

        result = runner.invoke(app, ["deps", str(tmp_path)])

        # lodashe is not in npm registry, so flagged as hallucinated
        assert "DEP001" in result.stdout  # Hallucinated
        assert "lodashe" in result.stdout

    def test_deps_command_json_output(self, tmp_path: Path):
        """Test deps command with JSON output."""
        (tmp_path / "requirements.txt").write_text("requests\n")

        result = runner.invoke(app, ["deps", str(tmp_path), "--format", "json"])

        import json
        data = json.loads(result.stdout)
        assert "files_scanned" in data
        assert "findings" in data

    def test_deps_command_ci_mode(self, tmp_path: Path):
        """Test deps command in CI mode."""
        (tmp_path / "requirements.txt").write_text("requests\n")

        result = runner.invoke(app, ["deps", str(tmp_path), "--ci"])

        assert "\x1b[" not in result.stdout  # No ANSI codes

    def test_scan_with_include_deps(self, tmp_path: Path):
        """Test scan command with --include-deps."""
        (tmp_path / "app.py").write_text('query = f"SELECT * FROM {x}"')
        (tmp_path / "requirements.txt").write_text("requets\n")

        result = runner.invoke(app, ["scan", str(tmp_path), "--include-deps"])

        assert "INJ001" in result.stdout  # Code issue
        # requets is not in PyPI registry, so flagged as hallucinated
        assert "DEP001" in result.stdout  # Dependency issue (hallucinated)

    def test_mixed_project_full_scan(self, tmp_path: Path):
        """Test full scan of mixed Python/JS project with deps."""
        (tmp_path / "app.py").write_text("x = 1")
        (tmp_path / "app.js").write_text("const x = 1;")
        (tmp_path / "requirements.txt").write_text("requests\n")
        (tmp_path / "package.json").write_text('{"dependencies": {"lodash": "4.0.0"}}')

        result = runner.invoke(app, ["scan", str(tmp_path), "--include-deps"])

        assert result.exit_code == 0  # No issues

    def test_deps_nonexistent_path(self):
        """Test deps command with non-existent path."""
        result = runner.invoke(app, ["deps", "/nonexistent/path"])

        assert result.exit_code == 1
        assert "does not exist" in result.stdout

    def test_deps_file_not_directory(self, tmp_path: Path):
        """Test deps command with file instead of directory."""
        file_path = tmp_path / "test.txt"
        file_path.write_text("test")

        result = runner.invoke(app, ["deps", str(file_path)])

        assert result.exit_code == 1
        assert "must be a directory" in result.stdout

    def test_deps_fail_on_high(self, tmp_path: Path):
        """Test deps --fail-on high with hallucinated package."""
        (tmp_path / "requirements.txt").write_text("requets\n")

        result = runner.invoke(app, ["deps", str(tmp_path), "--fail-on", "high"])

        # requets is hallucinated (HIGH severity), so should fail
        assert result.exit_code == 1

    def test_deps_fail_on_with_clean_deps(self, tmp_path: Path):
        """Test deps --fail-on with clean dependencies."""
        (tmp_path / "requirements.txt").write_text("requests\n")

        result = runner.invoke(app, ["deps", str(tmp_path), "--fail-on", "high"])

        assert result.exit_code == 0
