"""Tests for Go parser using tree-sitter."""

from pathlib import Path

import pytest

from hackmenot.parsers.golang import GoParser, GoCallInfo, GoAssignmentInfo, GoStringInfo, GoParseResult


class TestGoParserBasics:
    """Test basic Go parser functionality."""

    def test_parse_simple_function_call(self):
        """Test parsing a simple fmt.Println call."""
        parser = GoParser()
        source = '''package main

import "fmt"

func main() {
    fmt.Println("Hello, World!")
}
'''
        result = parser.parse_string(source)

        assert not result.has_error
        calls = result.get_calls()
        call_names = [c.name for c in calls]
        assert "fmt.Println" in call_names

    def test_parse_db_query_call(self):
        """Test parsing a database query call."""
        parser = GoParser()
        source = '''package main

func queryUser(db *sql.DB, userID string) {
    db.Query("SELECT * FROM users WHERE id = " + userID)
}
'''
        result = parser.parse_string(source)

        calls = result.get_calls()
        call_names = [c.name for c in calls]
        assert "db.Query" in call_names

    def test_parse_exec_command_call(self):
        """Test parsing exec.Command call."""
        parser = GoParser()
        source = '''package main

import "os/exec"

func runCommand(cmd string) {
    exec.Command("sh", "-c", cmd)
}
'''
        result = parser.parse_string(source)

        calls = result.get_calls()
        call_names = [c.name for c in calls]
        assert "exec.Command" in call_names


class TestGoAssignmentExtraction:
    """Test Go assignment extraction."""

    def test_parse_variable_assignment_with_password(self):
        """Test parsing variable assignment containing password."""
        parser = GoParser()
        source = '''package main

func main() {
    password := "supersecret123"
    apiKey := "AKIAIOSFODNN7EXAMPLE"
}
'''
        result = parser.parse_string(source)

        assignments = result.get_assignments()
        var_names = [a.target for a in assignments]
        assert "password" in var_names
        assert "apiKey" in var_names

    def test_parse_regular_assignment(self):
        """Test parsing regular = assignment."""
        parser = GoParser()
        source = '''package main

var secret string

func main() {
    secret = "hidden_value"
}
'''
        result = parser.parse_string(source)

        assignments = result.get_assignments()
        var_names = [a.target for a in assignments]
        assert "secret" in var_names


class TestGoStringExtraction:
    """Test Go string literal extraction."""

    def test_parse_string_literals(self):
        """Test parsing string literals."""
        parser = GoParser()
        source = '''package main

func main() {
    query := "SELECT * FROM users"
    msg := "Hello World"
}
'''
        result = parser.parse_string(source)

        strings = result.get_strings()
        string_values = [s.value for s in strings]
        assert "SELECT * FROM users" in string_values
        assert "Hello World" in string_values

    def test_parse_raw_string_literals(self):
        """Test parsing raw string literals (backtick strings)."""
        parser = GoParser()
        source = '''package main

func main() {
    query := `SELECT *
FROM users
WHERE id = ?`
}
'''
        result = parser.parse_string(source)

        strings = result.get_strings()
        # Find a string containing SELECT
        sql_strings = [s for s in strings if "SELECT" in s.value]
        assert len(sql_strings) >= 1

    def test_parse_fmt_sprintf_formatted_string(self):
        """Test parsing fmt.Sprintf as formatted string."""
        parser = GoParser()
        source = '''package main

import "fmt"

func main() {
    name := "Alice"
    msg := fmt.Sprintf("Hello, %s!", name)
}
'''
        result = parser.parse_string(source)

        calls = result.get_calls()
        sprintf_calls = [c for c in calls if c.name == "fmt.Sprintf"]
        assert len(sprintf_calls) >= 1
        # Check arguments are captured
        assert len(sprintf_calls[0].args) >= 1


class TestGoFileOperations:
    """Test file-based parsing operations."""

    def test_parse_file_from_disk(self, tmp_path: Path):
        """Test parsing a Go file from disk."""
        parser = GoParser()
        go_file = tmp_path / "main.go"
        go_file.write_text('''package main

import "fmt"

func main() {
    fmt.Println("test")
}
''')
        result = parser.parse_file(go_file)

        assert not result.has_error
        calls = result.get_calls()
        call_names = [c.name for c in calls]
        assert "fmt.Println" in call_names

    def test_parse_empty_file(self, tmp_path: Path):
        """Test parsing an empty Go file."""
        parser = GoParser()
        go_file = tmp_path / "empty.go"
        go_file.write_text("")

        result = parser.parse_file(go_file)

        assert not result.has_error

    def test_parse_invalid_go_code(self, tmp_path: Path):
        """Test parsing invalid Go code doesn't crash."""
        parser = GoParser()
        go_file = tmp_path / "invalid.go"
        go_file.write_text('''package main

func broken( {
    // syntax error
}
''')
        result = parser.parse_file(go_file)

        # Should not crash, tree-sitter is error tolerant
        assert result is not None


class TestGoMethodCallExtraction:
    """Test method call extraction on objects."""

    def test_parse_method_calls_on_objects(self):
        """Test parsing method calls on objects."""
        parser = GoParser()
        source = '''package main

func example() {
    client := &http.Client{}
    resp, _ := client.Get("http://example.com")
    resp.Body.Close()
}
'''
        result = parser.parse_string(source)

        calls = result.get_calls()
        call_names = [c.name for c in calls]
        assert "client.Get" in call_names or "http.Client" in call_names

    def test_call_info_captures_arguments(self):
        """Test that CallInfo captures function arguments."""
        parser = GoParser()
        source = '''package main

import "os/exec"

func main() {
    exec.Command("bash", "-c", "echo hello")
}
'''
        result = parser.parse_string(source)

        calls = result.get_calls()
        exec_calls = [c for c in calls if "Command" in c.name]
        assert len(exec_calls) >= 1
        # Should have captured arguments
        assert len(exec_calls[0].args) >= 1


class TestGoSecurityPatterns:
    """Test security-relevant patterns."""

    def test_parse_tls_config_insecure_skip_verify(self):
        """Test parsing TLS config with InsecureSkipVerify."""
        parser = GoParser()
        source = '''package main

import "crypto/tls"

func insecureClient() {
    config := &tls.Config{
        InsecureSkipVerify: true,
    }
}
'''
        result = parser.parse_string(source)

        # Should extract assignments or the config literal
        assignments = result.get_assignments()
        # At minimum the config assignment should be found
        assert len(assignments) >= 1


class TestGoImportExtraction:
    """Test import statement extraction."""

    def test_parse_import_statements(self):
        """Test parsing import statements."""
        parser = GoParser()
        source = '''package main

import (
    "fmt"
    "os/exec"
    "database/sql"
)

func main() {}
'''
        result = parser.parse_string(source)

        imports = result.get_imports()
        assert "fmt" in imports
        assert "os/exec" in imports
        assert "database/sql" in imports

    def test_parse_single_import(self):
        """Test parsing single import statement."""
        parser = GoParser()
        source = '''package main

import "fmt"

func main() {
    fmt.Println("hello")
}
'''
        result = parser.parse_string(source)

        imports = result.get_imports()
        assert "fmt" in imports
