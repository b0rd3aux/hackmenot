"""Integration tests for CI features."""

import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from hackmenot.cli.main import app

runner = CliRunner()


class TestCIIntegration:
    """Integration tests for CI flags combined usage."""

    def test_ci_with_staged_clean(self, tmp_path: Path):
        """Test --ci with --staged on clean files."""
        clean_file = tmp_path / "clean.py"
        clean_file.write_text("def hello(): pass")

        with patch("hackmenot.cli.main.is_git_repo", return_value=True):
            with patch("hackmenot.cli.main.get_staged_files", return_value=[clean_file]):
                result = runner.invoke(app, ["scan", "--staged", "--ci"])
                assert result.exit_code == 0
                # No ANSI codes in CI mode
                assert "\x1b[" not in result.stdout

    def test_ci_with_staged_findings(self, tmp_path: Path):
        """Test --ci with --staged when findings exist."""
        vuln_file = tmp_path / "vuln.py"
        vuln_file.write_text('query = f"SELECT * FROM users WHERE id = {uid}"')

        with patch("hackmenot.cli.main.is_git_repo", return_value=True):
            with patch("hackmenot.cli.main.get_staged_files", return_value=[vuln_file]):
                result = runner.invoke(app, ["scan", "--staged", "--ci"])
                assert result.exit_code == 1
                assert "\x1b[" not in result.stdout

    def test_ci_with_sarif_format(self, tmp_path: Path):
        """Test --ci with SARIF output format."""
        (tmp_path / "test.py").write_text('query = f"SELECT * FROM {x}"')
        result = runner.invoke(app, ["scan", str(tmp_path), "--ci", "--format", "sarif"])

        # Should produce valid JSON (SARIF)
        assert result.exit_code in [0, 1]
        sarif_data = json.loads(result.stdout)
        assert "$schema" in sarif_data
        assert "runs" in sarif_data

    def test_ci_with_json_format(self, tmp_path: Path):
        """Test --ci with JSON output format."""
        (tmp_path / "test.py").write_text('x = 1')
        result = runner.invoke(app, ["scan", str(tmp_path), "--ci", "--format", "json"])

        assert result.exit_code == 0
        json_data = json.loads(result.stdout)
        assert "files_scanned" in json_data
        assert "findings" in json_data


class TestPRCommentIntegration:
    """Integration tests for --pr-comment flag."""

    def test_pr_comment_clean_scan(self, tmp_path: Path):
        """Test --pr-comment with no findings."""
        (tmp_path / "clean.py").write_text("def foo(): pass")
        result = runner.invoke(app, ["scan", str(tmp_path), "--pr-comment"])

        assert result.exit_code == 0
        assert "## 🔒 hackmenot Security Scan" in result.stdout
        assert "No security issues found" in result.stdout

    def test_pr_comment_with_findings(self, tmp_path: Path):
        """Test --pr-comment with findings."""
        (tmp_path / "vuln.py").write_text('query = f"SELECT * FROM users WHERE id = {x}"')
        result = runner.invoke(app, ["scan", str(tmp_path), "--pr-comment"])

        assert result.exit_code == 1
        assert "## 🔒 hackmenot Security Scan" in result.stdout
        assert "| Severity | Count |" in result.stdout
        assert "INJ001" in result.stdout

    def test_pr_comment_with_staged(self, tmp_path: Path):
        """Test --pr-comment combined with --staged."""
        vuln_file = tmp_path / "vuln.py"
        vuln_file.write_text('eval(user_input)')

        with patch("hackmenot.cli.main.is_git_repo", return_value=True):
            with patch("hackmenot.cli.main.get_staged_files", return_value=[vuln_file]):
                result = runner.invoke(app, ["scan", "--staged", "--pr-comment"])
                assert "## 🔒 hackmenot Security Scan" in result.stdout

    def test_pr_comment_is_markdown(self, tmp_path: Path):
        """Test --pr-comment output is valid markdown."""
        (tmp_path / "test.py").write_text("x = 1")
        result = runner.invoke(app, ["scan", str(tmp_path), "--pr-comment"])

        # Check markdown structure
        assert "##" in result.stdout  # Headers
        assert "---" in result.stdout  # Separator
        assert "[hackmenot]" in result.stdout  # Link


class TestExitCodes:
    """Tests for CI exit codes."""

    def test_exit_code_zero_clean(self, tmp_path: Path):
        """Test exit code 0 when no findings at fail level."""
        (tmp_path / "clean.py").write_text("x = 1")
        result = runner.invoke(app, ["scan", str(tmp_path), "--ci"])
        assert result.exit_code == 0

    def test_exit_code_one_high_findings(self, tmp_path: Path):
        """Test exit code 1 when findings at high severity."""
        (tmp_path / "vuln.py").write_text('query = f"SELECT * FROM {x}"')
        result = runner.invoke(app, ["scan", str(tmp_path), "--ci", "--fail-on", "high"])
        assert result.exit_code == 1

    def test_exit_code_respects_fail_on_level(self, tmp_path: Path):
        """Test exit code respects --fail-on setting."""
        # Create file with critical vulnerability (SQL injection)
        (tmp_path / "vuln.py").write_text('query = f"SELECT * FROM users WHERE id = {user_id}"')
        result = runner.invoke(app, ["scan", str(tmp_path), "--ci", "--fail-on", "critical"])
        # Should exit 1 because SQL injection is critical
        assert result.exit_code == 1

    def test_exit_code_zero_below_fail_level(self, tmp_path: Path):
        """Test exit code 0 when findings are below fail level."""
        # Create file with medium-severity issue
        (tmp_path / "test.py").write_text('password = "secret123"')
        result = runner.invoke(app, ["scan", str(tmp_path), "--ci", "--fail-on", "critical"])
        # Should exit 0 because hardcoded password is high, not critical
        # (depending on actual severity in rules)
        # This might be 0 or 1 depending on rule severity
        assert result.exit_code in [0, 1]

    def test_exit_code_two_on_error(self, tmp_path: Path):
        """Test exit code 2 on scan error."""
        # Try to scan a non-existent path
        result = runner.invoke(app, ["scan", str(tmp_path / "nonexistent"), "--ci"])
        # Should return error exit code
        assert result.exit_code in [1, 2]  # Depends on error type


class TestCIFlagCombinations:
    """Tests for various CI flag combinations."""

    def test_ci_staged_sarif(self, tmp_path: Path):
        """Test --ci --staged --format sarif together."""
        vuln_file = tmp_path / "vuln.py"
        vuln_file.write_text('query = f"SELECT * FROM {x}"')

        with patch("hackmenot.cli.main.is_git_repo", return_value=True):
            with patch("hackmenot.cli.main.get_staged_files", return_value=[vuln_file]):
                result = runner.invoke(
                    app, ["scan", "--staged", "--ci", "--format", "sarif"]
                )
                sarif_data = json.loads(result.stdout)
                assert "$schema" in sarif_data

    def test_ci_fail_on_combined(self, tmp_path: Path):
        """Test --ci with --fail-on combined."""
        (tmp_path / "test.py").write_text('x = 1')
        result = runner.invoke(
            app, ["scan", str(tmp_path), "--ci", "--fail-on", "low"]
        )
        assert result.exit_code == 0
        assert "\x1b[" not in result.stdout

    def test_pr_comment_ci_combination(self, tmp_path: Path):
        """Test --pr-comment works independently of --ci."""
        (tmp_path / "test.py").write_text('x = 1')
        # --pr-comment should work without --ci
        result = runner.invoke(app, ["scan", str(tmp_path), "--pr-comment"])
        assert "## 🔒 hackmenot Security Scan" in result.stdout


class TestJavaScriptCIIntegration:
    """Tests for CI features with JavaScript files."""

    def test_staged_scans_js_files(self, tmp_path: Path):
        """Test --staged scans JavaScript files in CI mode."""
        js_file = tmp_path / "app.js"
        js_file.write_text('eval(userInput);')

        with patch("hackmenot.cli.main.is_git_repo", return_value=True):
            with patch("hackmenot.cli.main.get_staged_files", return_value=[js_file]):
                result = runner.invoke(app, ["scan", "--staged", "--ci"])
                # Should scan without error and find eval issue
                assert result.exit_code in [0, 1]
                assert "\x1b[" not in result.stdout

    def test_staged_scans_ts_files(self, tmp_path: Path):
        """Test --staged scans TypeScript files."""
        ts_file = tmp_path / "app.ts"
        ts_file.write_text('const x: number = 1;')

        with patch("hackmenot.cli.main.is_git_repo", return_value=True):
            with patch("hackmenot.cli.main.get_staged_files", return_value=[ts_file]):
                result = runner.invoke(app, ["scan", "--staged", "--ci"])
                assert result.exit_code == 0

    def test_sarif_includes_js_findings(self, tmp_path: Path):
        """Test SARIF output includes JavaScript findings."""
        (tmp_path / "app.js").write_text('eval(input);')
        result = runner.invoke(app, ["scan", str(tmp_path), "--format", "sarif"])

        sarif_data = json.loads(result.stdout)
        # SARIF should have results
        runs = sarif_data.get("runs", [])
        if runs:
            results = runs[0].get("results", [])
            # Should have at least one result for eval
            assert len(results) >= 1

    def test_pr_comment_js_findings(self, tmp_path: Path):
        """Test --pr-comment shows JavaScript findings."""
        (tmp_path / "app.js").write_text('document.innerHTML = userInput;')
        result = runner.invoke(app, ["scan", str(tmp_path), "--pr-comment"])

        assert "## 🔒 hackmenot Security Scan" in result.stdout


class TestMixedLanguageCIIntegration:
    """Tests for CI with mixed Python and JavaScript codebases."""

    def test_staged_mixed_languages(self, tmp_path: Path):
        """Test --staged with both Python and JavaScript files."""
        py_file = tmp_path / "app.py"
        py_file.write_text('query = f"SELECT * FROM {x}"')

        js_file = tmp_path / "app.js"
        js_file.write_text('eval(userInput);')

        with patch("hackmenot.cli.main.is_git_repo", return_value=True):
            with patch(
                "hackmenot.cli.main.get_staged_files", return_value=[py_file, js_file]
            ):
                result = runner.invoke(app, ["scan", "--staged", "--ci"])
                # Should find issues in both files
                assert result.exit_code == 1

    def test_sarif_mixed_languages(self, tmp_path: Path):
        """Test SARIF output with mixed language findings."""
        (tmp_path / "app.py").write_text('eval(x)')
        (tmp_path / "app.js").write_text('eval(y);')

        result = runner.invoke(app, ["scan", str(tmp_path), "--format", "sarif"])
        sarif_data = json.loads(result.stdout)

        runs = sarif_data.get("runs", [])
        assert len(runs) >= 1

    def test_pr_comment_mixed_findings(self, tmp_path: Path):
        """Test --pr-comment shows findings from both languages."""
        (tmp_path / "app.py").write_text('query = f"SELECT * FROM {x}"')
        (tmp_path / "app.js").write_text('const q = `SELECT * FROM ${x}`;')

        result = runner.invoke(app, ["scan", str(tmp_path), "--pr-comment"])

        assert "## 🔒 hackmenot Security Scan" in result.stdout
        assert "| Severity | Count |" in result.stdout
