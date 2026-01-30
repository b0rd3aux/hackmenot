"""Tests for Python AST parser."""

from pathlib import Path

from hackmenot.parsers.python import PythonParser


def test_parser_can_parse_file(fixtures_dir: Path):
    """Test parser can parse a Python file."""
    parser = PythonParser()
    file_path = fixtures_dir / "python" / "simple_function.py"
    result = parser.parse_file(file_path)
    assert result is not None
    assert result.file_path == file_path


def test_parser_extracts_functions(fixtures_dir: Path):
    """Test parser extracts function definitions."""
    parser = PythonParser()
    file_path = fixtures_dir / "python" / "simple_function.py"
    result = parser.parse_file(file_path)
    functions = result.get_functions()

    assert len(functions) >= 2
    func_names = [f.name for f in functions]
    assert "hello" in func_names
    assert "get_users" in func_names


def test_parser_extracts_function_decorators(fixtures_dir: Path):
    """Test parser extracts decorators from functions."""
    parser = PythonParser()
    file_path = fixtures_dir / "python" / "simple_function.py"
    result = parser.parse_file(file_path)
    functions = result.get_functions()

    get_users = next(f for f in functions if f.name == "get_users")
    assert len(get_users.decorators) > 0
    assert any("route" in d for d in get_users.decorators)


def test_parser_extracts_fstrings(fixtures_dir: Path):
    """Test parser extracts f-string expressions."""
    parser = PythonParser()
    file_path = fixtures_dir / "python" / "simple_function.py"
    result = parser.parse_file(file_path)
    fstrings = result.get_fstrings()

    assert len(fstrings) >= 2
    sql_fstrings = [f for f in fstrings if "SELECT" in f.value]
    assert len(sql_fstrings) >= 1


def test_parser_extracts_classes(fixtures_dir: Path):
    """Test parser extracts class definitions."""
    parser = PythonParser()
    file_path = fixtures_dir / "python" / "simple_function.py"
    result = parser.parse_file(file_path)
    classes = result.get_classes()

    assert len(classes) >= 1
    assert any(c.name == "UserService" for c in classes)


def test_parser_handles_syntax_error(tmp_path: Path):
    """Test parser handles invalid Python gracefully."""
    parser = PythonParser()
    bad_file = tmp_path / "bad.py"
    bad_file.write_text("def broken(\n")

    result = parser.parse_file(bad_file)
    assert result.has_error
    assert result.error_message is not None
