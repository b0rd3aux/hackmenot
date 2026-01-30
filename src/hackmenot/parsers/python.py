"""Python AST parser."""

import ast
from pathlib import Path

from hackmenot.parsers.base import (
    BaseParser,
    ClassInfo,
    FStringInfo,
    FunctionInfo,
    ParseResult,
)


class PythonParser(BaseParser):
    """Parser for Python source files using the ast module."""

    def parse_file(self, file_path: Path) -> ParseResult:
        """Parse a Python file."""
        try:
            source = file_path.read_text(encoding="utf-8")
            return self.parse_string(source, str(file_path))
        except Exception as e:
            return ParseResult(
                file_path=file_path,
                has_error=True,
                error_message=str(e),
            )

    def parse_string(self, source: str, filename: str = "<string>") -> ParseResult:
        """Parse Python source code string."""
        file_path = Path(filename)

        try:
            tree = ast.parse(source, filename=filename)
        except SyntaxError as e:
            return ParseResult(
                file_path=file_path,
                has_error=True,
                error_message=f"Syntax error: {e}",
            )

        visitor = _PythonASTVisitor()
        visitor.visit(tree)

        return ParseResult(
            file_path=file_path,
            _functions=visitor.functions,
            _classes=visitor.classes,
            _fstrings=visitor.fstrings,
            _raw_ast=tree,
        )


class _PythonASTVisitor(ast.NodeVisitor):
    """AST visitor that extracts relevant information."""

    def __init__(self) -> None:
        self.functions: list[FunctionInfo] = []
        self.classes: list[ClassInfo] = []
        self.fstrings: list[FStringInfo] = []
        self._current_class: ClassInfo | None = None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definition."""
        func_info = self._extract_function_info(node)

        if self._current_class is not None:
            self._current_class.methods.append(func_info)
        else:
            self.functions.append(func_info)

        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit async function definition."""
        func_info = self._extract_function_info(node)

        if self._current_class is not None:
            self._current_class.methods.append(func_info)
        else:
            self.functions.append(func_info)

        self.generic_visit(node)

    def _extract_function_info(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> FunctionInfo:
        """Extract function information from AST node."""
        decorators = []
        for dec in node.decorator_list:
            decorators.append(ast.unparse(dec))

        args = []
        for arg in node.args.args:
            args.append(arg.arg)

        body_end = node.end_lineno if node.end_lineno else node.lineno

        return FunctionInfo(
            name=node.name,
            line_number=node.lineno,
            column=node.col_offset,
            decorators=decorators,
            args=args,
            body_start=node.lineno,
            body_end=body_end,
        )

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit class definition."""
        bases = [ast.unparse(base) for base in node.bases]

        class_info = ClassInfo(
            name=node.name,
            line_number=node.lineno,
            column=node.col_offset,
            bases=bases,
        )

        old_class = self._current_class
        self._current_class = class_info

        self.generic_visit(node)

        self._current_class = old_class
        self.classes.append(class_info)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        """Visit f-string (JoinedStr in AST)."""
        parts = []
        variables = []

        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
            elif isinstance(value, ast.FormattedValue):
                var_repr = ast.unparse(value.value)
                parts.append(f"{{{var_repr}}}")
                variables.append(var_repr)

        fstring_info = FStringInfo(
            value="".join(parts),
            line_number=node.lineno,
            column=node.col_offset,
            variables=variables,
        )
        self.fstrings.append(fstring_info)

        self.generic_visit(node)
