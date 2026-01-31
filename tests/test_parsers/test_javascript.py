"""Tests for JavaScript/TypeScript parser using tree-sitter."""

from pathlib import Path

import pytest

from hackmenot.parsers.javascript import JavaScriptParser


class TestJavaScriptParserBasics:
    """Test basic parser functionality."""

    def test_parser_can_parse_js_file(self, fixtures_dir: Path):
        """Test parser can parse a JavaScript file."""
        parser = JavaScriptParser()
        file_path = fixtures_dir / "javascript" / "sample.js"
        result = parser.parse_file(file_path)

        assert result is not None
        assert result.file_path == file_path
        assert not result.has_error

    def test_supported_extensions(self):
        """Test parser supports JS/TS/JSX/TSX extensions."""
        parser = JavaScriptParser()
        expected = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}
        assert parser.SUPPORTED_EXTENSIONS == expected


class TestFunctionCallExtraction:
    """Test function call extraction."""

    def test_parser_extracts_function_calls(self, fixtures_dir: Path):
        """Test parser extracts function call information."""
        parser = JavaScriptParser()
        file_path = fixtures_dir / "javascript" / "sample.js"
        result = parser.parse_file(file_path)
        calls = result.get_calls()

        assert len(calls) > 0

        # Check for specific function calls
        call_names = [c.name for c in calls]
        assert "fetch" in call_names
        assert "console.log" in call_names

    def test_extracts_call_arguments(self, fixtures_dir: Path):
        """Test parser extracts function call arguments."""
        parser = JavaScriptParser()
        file_path = fixtures_dir / "javascript" / "sample.js"
        result = parser.parse_file(file_path)
        calls = result.get_calls()

        # Find fetch call with URL argument
        fetch_calls = [c for c in calls if c.name == "fetch"]
        assert len(fetch_calls) > 0
        # At least one fetch call should have arguments
        assert any(len(c.arguments) > 0 for c in fetch_calls)

    def test_extracts_nested_calls(self, fixtures_dir: Path):
        """Test parser extracts nested function calls."""
        parser = JavaScriptParser()
        file_path = fixtures_dir / "javascript" / "sample.js"
        result = parser.parse_file(file_path)
        calls = result.get_calls()

        call_names = [c.name for c in calls]
        # JSON.parse and localStorage.getItem should both be extracted
        assert "JSON.parse" in call_names
        assert "localStorage.getItem" in call_names


class TestTemplateLiteralExtraction:
    """Test template literal extraction."""

    def test_parser_extracts_template_literals(self, fixtures_dir: Path):
        """Test parser extracts template literal strings."""
        parser = JavaScriptParser()
        file_path = fixtures_dir / "javascript" / "sample.js"
        result = parser.parse_file(file_path)
        templates = result.get_template_literals()

        assert len(templates) > 0

        # Check for SQL template
        sql_templates = [t for t in templates if "SELECT" in t.value]
        assert len(sql_templates) >= 1

    def test_template_literal_has_interpolations(self, fixtures_dir: Path):
        """Test parser extracts interpolation expressions from templates."""
        parser = JavaScriptParser()
        file_path = fixtures_dir / "javascript" / "sample.js"
        result = parser.parse_file(file_path)
        templates = result.get_template_literals()

        # Find template with interpolation
        templates_with_vars = [t for t in templates if len(t.expressions) > 0]
        assert len(templates_with_vars) > 0


class TestAssignmentExtraction:
    """Test assignment extraction."""

    def test_parser_extracts_assignments(self, fixtures_dir: Path):
        """Test parser extracts variable assignments."""
        parser = JavaScriptParser()
        file_path = fixtures_dir / "javascript" / "sample.js"
        result = parser.parse_file(file_path)
        assignments = result.get_assignments()

        assert len(assignments) > 0

        # Check for specific assignments
        var_names = [a.name for a in assignments]
        assert "userId" in var_names
        assert "apiKey" in var_names
        assert "password" in var_names

    def test_assignment_has_value_info(self, fixtures_dir: Path):
        """Test parser extracts assignment value type."""
        parser = JavaScriptParser()
        file_path = fixtures_dir / "javascript" / "sample.js"
        result = parser.parse_file(file_path)
        assignments = result.get_assignments()

        # Find apiKey assignment with string value
        api_key = next((a for a in assignments if a.name == "apiKey"), None)
        assert api_key is not None
        assert api_key.value_type == "string"


class TestJSXHandling:
    """Test JSX/React code handling."""

    def test_parser_handles_jsx(self, fixtures_dir: Path):
        """Test parser can parse JSX files."""
        parser = JavaScriptParser()
        file_path = fixtures_dir / "javascript" / "sample.jsx"
        result = parser.parse_file(file_path)

        assert not result.has_error
        assert result.file_path == file_path

    def test_parser_extracts_jsx_elements(self, fixtures_dir: Path):
        """Test parser extracts JSX element information."""
        parser = JavaScriptParser()
        file_path = fixtures_dir / "javascript" / "sample.jsx"
        result = parser.parse_file(file_path)
        jsx_elements = result.get_jsx_elements()

        assert len(jsx_elements) > 0

        # Check for specific elements
        element_names = [e.name for e in jsx_elements]
        assert "div" in element_names

    def test_parser_extracts_dangerous_jsx_attributes(self, fixtures_dir: Path):
        """Test parser extracts dangerous JSX attributes like dangerouslySetInnerHTML."""
        parser = JavaScriptParser()
        file_path = fixtures_dir / "javascript" / "sample.jsx"
        result = parser.parse_file(file_path)
        jsx_elements = result.get_jsx_elements()

        # Find element with dangerouslySetInnerHTML
        dangerous_elements = [
            e for e in jsx_elements
            if any("dangerouslySetInnerHTML" in attr for attr in e.attributes)
        ]
        assert len(dangerous_elements) >= 1


class TestTypeScriptHandling:
    """Test TypeScript code handling."""

    def test_parser_handles_typescript(self, fixtures_dir: Path):
        """Test parser can parse TypeScript files."""
        parser = JavaScriptParser()
        file_path = fixtures_dir / "javascript" / "sample.ts"
        result = parser.parse_file(file_path)

        assert not result.has_error
        assert result.file_path == file_path

    def test_parser_extracts_from_typescript(self, fixtures_dir: Path):
        """Test parser extracts patterns from TypeScript."""
        parser = JavaScriptParser()
        file_path = fixtures_dir / "javascript" / "sample.ts"
        result = parser.parse_file(file_path)

        # Should still extract function calls even with type annotations
        calls = result.get_calls()
        call_names = [c.name for c in calls]
        assert "fetch" in call_names

        # Should extract template literals
        templates = result.get_template_literals()
        assert len(templates) > 0


class TestErrorHandling:
    """Test error handling."""

    def test_parser_handles_syntax_error(self, tmp_path: Path):
        """Test parser handles syntax errors gracefully."""
        parser = JavaScriptParser()
        bad_file = tmp_path / "bad.js"
        bad_file.write_text("function broken( {\n")

        result = parser.parse_file(bad_file)
        # Tree-sitter is error-tolerant, but we should mark partial parses
        # Check that we don't crash and get a result
        assert result is not None

    def test_parser_handles_missing_file(self, tmp_path: Path):
        """Test parser handles missing files gracefully."""
        parser = JavaScriptParser()
        missing_file = tmp_path / "nonexistent.js"

        result = parser.parse_file(missing_file)
        assert result.has_error
        assert result.error_message is not None

    def test_parser_handles_empty_file(self, tmp_path: Path):
        """Test parser handles empty files."""
        parser = JavaScriptParser()
        empty_file = tmp_path / "empty.js"
        empty_file.write_text("")

        result = parser.parse_file(empty_file)
        assert not result.has_error


class TestParseString:
    """Test parsing source code strings directly."""

    def test_parse_string_basic(self):
        """Test parsing a source code string."""
        parser = JavaScriptParser()
        source = """
        const x = fetch('/api/data');
        const query = `SELECT * FROM ${table}`;
        """
        result = parser.parse_string(source)

        assert not result.has_error
        assert len(result.get_calls()) > 0
        assert len(result.get_template_literals()) > 0

    def test_parse_string_with_filename(self):
        """Test parsing with a custom filename."""
        parser = JavaScriptParser()
        source = "const x = 1;"
        result = parser.parse_string(source, filename="test.js")

        assert not result.has_error
        assert result.file_path == Path("test.js")
