"""Tests for Go pattern matching in the RulesEngine."""

from pathlib import Path

import pytest

from hackmenot.core.models import Rule, Severity
from hackmenot.parsers.golang import GoParser
from hackmenot.rules.engine import RulesEngine


@pytest.fixture
def engine() -> RulesEngine:
    """Create a RulesEngine instance."""
    return RulesEngine()


@pytest.fixture
def parser() -> GoParser:
    """Create a GoParser instance."""
    return GoParser()


class TestGoCallPattern:
    """Tests for Go call pattern matching."""

    def test_detects_exec_command(self, engine: RulesEngine, parser: GoParser, tmp_path: Path):
        """Test detection of os/exec Command call."""
        rule = Rule(
            id="GO001",
            name="go-command-injection",
            severity=Severity.CRITICAL,
            category="injection",
            languages=["go"],
            description="Command injection vulnerability",
            message="exec.Command can be vulnerable to command injection",
            pattern={
                "type": "call",
                "names": ["exec.Command"],
            },
        )
        engine.register_rule(rule)

        go_file = tmp_path / "main.go"
        go_file.write_text("""
package main

import "os/exec"

func run() {
    cmd := exec.Command("bash", "-c", userInput)
    cmd.Run()
}
""")

        parse_result = parser.parse_file(go_file)
        findings = engine.check(parse_result, go_file)

        assert len(findings) == 1
        assert findings[0].rule_id == "GO001"
        assert "exec.Command" in findings[0].code_snippet

    def test_detects_multiple_calls(self, engine: RulesEngine, parser: GoParser, tmp_path: Path):
        """Test detection of multiple dangerous calls."""
        rule = Rule(
            id="GO002",
            name="go-sql-exec",
            severity=Severity.HIGH,
            category="injection",
            languages=["go"],
            description="SQL execution call",
            message="db.Exec can be vulnerable to SQL injection",
            pattern={
                "type": "call",
                "names": ["db.Exec", "db.Query"],
            },
        )
        engine.register_rule(rule)

        go_file = tmp_path / "main.go"
        go_file.write_text("""
package main

func query() {
    db.Exec("DELETE FROM users WHERE id = " + id)
    db.Query("SELECT * FROM users WHERE name = " + name)
}
""")

        parse_result = parser.parse_file(go_file)
        findings = engine.check(parse_result, go_file)

        assert len(findings) == 2

    def test_case_insensitive_call_matching(self, engine: RulesEngine, parser: GoParser, tmp_path: Path):
        """Test case-insensitive matching for call names."""
        rule = Rule(
            id="GO003",
            name="go-print",
            severity=Severity.LOW,
            category="logging",
            languages=["go"],
            description="Print call detected",
            message="Consider using structured logging",
            pattern={
                "type": "call",
                "names": ["fmt.print"],  # lowercase pattern
            },
        )
        engine.register_rule(rule)

        go_file = tmp_path / "main.go"
        go_file.write_text("""
package main

import "fmt"

func main() {
    fmt.Println("hello")
    fmt.Printf("world %s", name)
}
""")

        parse_result = parser.parse_file(go_file)
        findings = engine.check(parse_result, go_file)

        assert len(findings) == 2


class TestGoStringPattern:
    """Tests for Go string pattern matching."""

    def test_detects_hardcoded_password_in_assignment(self, engine: RulesEngine, parser: GoParser, tmp_path: Path):
        """Test detection of hardcoded password in variable assignment."""
        rule = Rule(
            id="GO004",
            name="go-hardcoded-secret",
            severity=Severity.HIGH,
            category="secrets",
            languages=["go"],
            description="Hardcoded secret",
            message="Hardcoded password detected",
            pattern={
                "type": "string",
                "contains": ["password", "secret"],
            },
        )
        engine.register_rule(rule)

        go_file = tmp_path / "main.go"
        go_file.write_text("""
package main

func connect() {
    password := "supersecret123"
    dbConnect(password)
}
""")

        parse_result = parser.parse_file(go_file)
        findings = engine.check(parse_result, go_file)

        # Should match both the assignment (password :=) and the string literal
        assert len(findings) >= 1

    def test_detects_secret_in_string_literal(self, engine: RulesEngine, parser: GoParser, tmp_path: Path):
        """Test detection of secrets in string literals."""
        rule = Rule(
            id="GO005",
            name="go-api-key",
            severity=Severity.HIGH,
            category="secrets",
            languages=["go"],
            description="API key in string",
            message="Hardcoded API key detected",
            pattern={
                "type": "string",
                "contains": ["api_key", "apikey", "API-KEY"],
            },
        )
        engine.register_rule(rule)

        go_file = tmp_path / "main.go"
        go_file.write_text("""
package main

func auth() {
    header := "X-API-KEY: sk-12345"
}
""")

        parse_result = parser.parse_file(go_file)
        findings = engine.check(parse_result, go_file)

        assert len(findings) >= 1

    def test_no_match_for_clean_code(self, engine: RulesEngine, parser: GoParser, tmp_path: Path):
        """Test no findings for clean code without secrets."""
        rule = Rule(
            id="GO006",
            name="go-secret-detector",
            severity=Severity.HIGH,
            category="secrets",
            languages=["go"],
            description="Secret detector",
            message="Secret detected",
            pattern={
                "type": "string",
                "contains": ["password", "secret", "api_key"],
            },
        )
        engine.register_rule(rule)

        go_file = tmp_path / "main.go"
        go_file.write_text("""
package main

func greet(name string) string {
    return "Hello, " + name
}
""")

        parse_result = parser.parse_file(go_file)
        findings = engine.check(parse_result, go_file)

        assert len(findings) == 0


class TestGoImportPattern:
    """Tests for Go import pattern matching."""

    def test_detects_unsafe_import(self, engine: RulesEngine, parser: GoParser, tmp_path: Path):
        """Test detection of unsafe package import."""
        rule = Rule(
            id="GO007",
            name="go-unsafe-import",
            severity=Severity.HIGH,
            category="unsafe",
            languages=["go"],
            description="Unsafe package import",
            message="unsafe package usage requires careful review",
            pattern={
                "type": "import",
                "names": ["unsafe"],
            },
        )
        engine.register_rule(rule)

        go_file = tmp_path / "main.go"
        go_file.write_text("""
package main

import (
    "fmt"
    "unsafe"
)

func main() {
    fmt.Println("hello")
}
""")

        parse_result = parser.parse_file(go_file)
        findings = engine.check(parse_result, go_file)

        assert len(findings) == 1
        assert findings[0].rule_id == "GO007"
        assert "unsafe" in findings[0].code_snippet

    def test_detects_crypto_md5_import(self, engine: RulesEngine, parser: GoParser, tmp_path: Path):
        """Test detection of weak crypto import."""
        rule = Rule(
            id="GO008",
            name="go-weak-crypto",
            severity=Severity.MEDIUM,
            category="crypto",
            languages=["go"],
            description="Weak crypto import",
            message="MD5 is cryptographically weak",
            pattern={
                "type": "import",
                "names": ["crypto/md5", "crypto/sha1"],
            },
        )
        engine.register_rule(rule)

        go_file = tmp_path / "main.go"
        go_file.write_text("""
package main

import "crypto/md5"

func hash(data []byte) {
    md5.Sum(data)
}
""")

        parse_result = parser.parse_file(go_file)
        findings = engine.check(parse_result, go_file)

        assert len(findings) == 1
        assert "crypto/md5" in findings[0].code_snippet


class TestGoLanguageFilter:
    """Tests for language filtering."""

    def test_go_rule_does_not_match_python_file(self, engine: RulesEngine, tmp_path: Path):
        """Test Go rules don't match Python files."""
        from hackmenot.parsers.python import PythonParser

        py_parser = PythonParser()

        rule = Rule(
            id="GO001",
            name="go-only-rule",
            severity=Severity.CRITICAL,
            category="test",
            languages=["go"],  # Go only
            description="Go only rule",
            message="Should not match Python files",
            pattern={
                "type": "call",
                "names": ["exec"],
            },
        )
        engine.register_rule(rule)

        py_file = tmp_path / "test.py"
        py_file.write_text('exec("print(1)")\n')

        parse_result = py_parser.parse_file(py_file)
        findings = engine.check(parse_result, py_file)

        assert len(findings) == 0

    def test_python_rule_does_not_match_go_file(self, engine: RulesEngine, parser: GoParser, tmp_path: Path):
        """Test Python rules don't match Go files."""
        rule = Rule(
            id="PY001",
            name="python-only-rule",
            severity=Severity.CRITICAL,
            category="test",
            languages=["python"],  # Python only
            description="Python only rule",
            message="Should not match Go files",
            pattern={
                "type": "call",
                "names": ["exec"],
            },
        )
        engine.register_rule(rule)

        go_file = tmp_path / "main.go"
        go_file.write_text("""
package main

func main() {
    exec.Command("ls")
}
""")

        parse_result = parser.parse_file(go_file)
        findings = engine.check(parse_result, go_file)

        assert len(findings) == 0
