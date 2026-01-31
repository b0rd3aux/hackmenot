"""Integration tests for Go scanning."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from hackmenot.cli.main import app
from hackmenot.core.scanner import Scanner

runner = CliRunner()


class TestGoIntegration:
    """End-to-end tests for scanning Go files."""

    def test_full_scan_go_project(self, tmp_path: Path):
        """Test full scan of Go project with multiple issues."""
        go_file = tmp_path / "main.go"
        go_file.write_text('''
package main

import (
    "crypto/md5"
    "database/sql"
    "os/exec"
    "unsafe"
)

func handler(userId string, db *sql.DB) {
    password := "secret123"
    query := "SELECT * FROM users WHERE id = " + userId
    db.Query(query)
    exec.Command("sh", "-c", userId)
    md5.New()
}
''')
        scanner = Scanner()
        result = scanner.scan([tmp_path])

        assert result.files_scanned == 1
        rule_ids = {f.rule_id for f in result.findings}
        # Should detect multiple issues
        assert "GO_INJ001" in rule_ids  # SQL injection
        assert "GO_INJ002" in rule_ids  # Command injection
        assert "GO_CRY001" in rule_ids  # Weak hash MD5
        assert "GO_UNS001" in rule_ids  # Unsafe package

    def test_go_cli_scan(self, tmp_path: Path):
        """Test CLI scan of Go files."""
        go_file = tmp_path / "main.go"
        go_file.write_text('''
package main

func main() {
    password := "hardcoded"
}
''')
        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert "GO_AUT001" in result.stdout or "password" in result.stdout.lower()

    def test_go_json_output(self, tmp_path: Path):
        """Test JSON output for Go scan."""
        go_file = tmp_path / "main.go"
        go_file.write_text('''
package main

import "crypto/md5"

func hash() { md5.New() }
''')
        result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
        import json
        data = json.loads(result.stdout)
        assert "findings" in data

    def test_clean_go_code_no_findings(self, tmp_path: Path):
        """Test that clean Go code has no findings."""
        go_file = tmp_path / "main.go"
        go_file.write_text('''
package main

import "fmt"

func main() {
    fmt.Println("Hello, World!")
}
''')
        scanner = Scanner()
        result = scanner.scan([tmp_path])
        assert len(result.findings) == 0

    def test_go_fail_on_high(self, tmp_path: Path):
        """Test --fail-on with Go findings."""
        go_file = tmp_path / "main.go"
        go_file.write_text('''
package main

import "unsafe"

func main() { _ = unsafe.Pointer(nil) }
''')
        result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "high"])
        assert result.exit_code == 1  # GO_UNS001 is HIGH
