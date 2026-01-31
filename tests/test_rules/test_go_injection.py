"""Tests for Go injection rules."""

from pathlib import Path

import pytest

from hackmenot.core.scanner import Scanner


class TestGoInjectionRules:
    """Tests for Go injection rule detection."""

    @pytest.fixture
    def scanner(self):
        return Scanner()

    def test_sql_injection_detected(self, scanner, tmp_path):
        """Test GO_INJ001 detects SQL injection."""
        go_file = tmp_path / "main.go"
        go_file.write_text('''
package main

func handler(userId string) {
    db.Query("SELECT * FROM users WHERE id = " + userId)
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "GO_INJ001"]
        assert len(findings) >= 1

    def test_command_injection_detected(self, scanner, tmp_path):
        """Test GO_INJ002 detects command injection."""
        go_file = tmp_path / "main.go"
        go_file.write_text('''
package main

import "os/exec"

func run(cmd string) {
    exec.Command("sh", "-c", cmd)
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "GO_INJ002"]
        assert len(findings) >= 1

    def test_path_traversal_detected(self, scanner, tmp_path):
        """Test GO_INJ003 detects path traversal."""
        go_file = tmp_path / "main.go"
        go_file.write_text('''
package main

import "path/filepath"

func serve(filename string) {
    filepath.Join("/uploads", filename)
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "GO_INJ003"]
        assert len(findings) >= 1

    def test_template_injection_detected(self, scanner, tmp_path):
        """Test GO_INJ006 detects template injection."""
        go_file = tmp_path / "main.go"
        go_file.write_text('''
package main

import "html/template"

func render(userInput string) {
    template.HTML(userInput)
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "GO_INJ006"]
        assert len(findings) >= 1

    def test_clean_code_no_findings(self, scanner, tmp_path):
        """Test that clean Go code has no injection findings."""
        go_file = tmp_path / "main.go"
        go_file.write_text('''
package main

func main() {
    fmt.Println("Hello, World!")
}
''')
        result = scanner.scan([tmp_path])
        injection_findings = [f for f in result.findings if f.rule_id.startswith("GO_INJ")]
        assert len(injection_findings) == 0
