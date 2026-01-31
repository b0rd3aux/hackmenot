"""Go parser using tree-sitter."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tree_sitter_go as ts_go
from tree_sitter import Language, Parser, Node

from hackmenot.parsers.base import BaseParser, ParseResult


@dataclass
class GoCallInfo:
    """Information about a function/method call in Go."""

    name: str
    args: list[str] = field(default_factory=list)
    line: int = 0
    column: int = 0


@dataclass
class GoAssignmentInfo:
    """Information about a variable assignment in Go."""

    target: str
    value: str = ""
    line: int = 0
    column: int = 0


@dataclass
class GoStringInfo:
    """Information about a string literal in Go."""

    value: str
    is_formatted: bool = False
    line: int = 0
    column: int = 0


@dataclass
class GoParseResult:
    """Result of parsing a Go file."""

    file_path: Path = field(default_factory=lambda: Path("<string>"))
    has_error: bool = False
    error_message: str | None = None
    _calls: list[GoCallInfo] = field(default_factory=list)
    _assignments: list[GoAssignmentInfo] = field(default_factory=list)
    _strings: list[GoStringInfo] = field(default_factory=list)
    _imports: list[str] = field(default_factory=list)
    _raw_tree: Any = None

    def get_calls(self) -> list[GoCallInfo]:
        """Get all function/method calls."""
        return self._calls

    def get_assignments(self) -> list[GoAssignmentInfo]:
        """Get all variable assignments."""
        return self._assignments

    def get_strings(self) -> list[GoStringInfo]:
        """Get all string literals."""
        return self._strings

    def get_imports(self) -> list[str]:
        """Get all import paths."""
        return self._imports


class GoParser(BaseParser):
    """Parser for Go source files using tree-sitter."""

    SUPPORTED_EXTENSIONS = {".go"}

    def __init__(self) -> None:
        """Initialize the parser with tree-sitter Go language."""
        self._language = Language(ts_go.language())
        self._parser = Parser(self._language)

    def parse_file(self, file_path: Path) -> GoParseResult:
        """Parse a Go file."""
        try:
            source = file_path.read_text(encoding="utf-8")
            result = self.parse_string(source, str(file_path))
            result.file_path = file_path
            return result
        except FileNotFoundError as e:
            return GoParseResult(
                file_path=file_path,
                has_error=True,
                error_message=f"File not found: {e}",
            )
        except Exception as e:
            return GoParseResult(
                file_path=file_path,
                has_error=True,
                error_message=str(e),
            )

    def parse_string(self, source: str, filename: str = "<string>") -> GoParseResult:
        """Parse Go source code string."""
        file_path = Path(filename)

        tree = self._parser.parse(bytes(source, "utf-8"))

        extractor = _GoExtractor(source)
        extractor.walk(tree.root_node)

        return GoParseResult(
            file_path=file_path,
            _calls=extractor.calls,
            _assignments=extractor.assignments,
            _strings=extractor.strings,
            _imports=extractor.imports,
            _raw_tree=tree,
        )


class _GoExtractor:
    """Walks the Go AST and extracts security-relevant patterns."""

    def __init__(self, source: str) -> None:
        self.source = source
        self.calls: list[GoCallInfo] = []
        self.assignments: list[GoAssignmentInfo] = []
        self.strings: list[GoStringInfo] = []
        self.imports: list[str] = []

    def walk(self, node: Node) -> None:
        """Walk the AST tree and extract patterns."""
        self._visit(node)

    def _visit(self, node: Node) -> None:
        """Visit a node and dispatch to the appropriate handler."""
        if node.type == "call_expression":
            self._visit_call_expression(node)
        elif node.type == "short_var_declaration":
            self._visit_short_var_declaration(node)
        elif node.type == "assignment_statement":
            self._visit_assignment_statement(node)
        elif node.type == "interpreted_string_literal":
            self._visit_interpreted_string_literal(node)
        elif node.type == "raw_string_literal":
            self._visit_raw_string_literal(node)
        elif node.type == "import_spec":
            self._visit_import_spec(node)

        # Continue walking children
        for child in node.children:
            self._visit(child)

    def _visit_call_expression(self, node: Node) -> None:
        """Extract function/method call information."""
        function_node = node.child_by_field_name("function")
        if function_node is None:
            return

        name = self._get_call_name(function_node)
        if name is None:
            return

        # Extract arguments
        arguments = []
        args_node = node.child_by_field_name("arguments")
        if args_node is not None:
            for child in args_node.children:
                if child.type not in ("(", ")", ","):
                    arg_text = self._get_node_text(child)
                    if arg_text:
                        arguments.append(arg_text)

        call_info = GoCallInfo(
            name=name,
            args=arguments,
            line=node.start_point[0] + 1,  # 1-indexed
            column=node.start_point[1],
        )
        self.calls.append(call_info)

    def _get_call_name(self, node: Node) -> str | None:
        """Get the name of a function being called."""
        if node.type == "identifier":
            return self._get_node_text(node)
        elif node.type == "selector_expression":
            # Handle cases like pkg.Func, obj.Method, obj.field.Method
            parts = []
            self._collect_selector_parts(node, parts)
            return ".".join(parts) if parts else None
        return None

    def _collect_selector_parts(self, node: Node, parts: list[str]) -> None:
        """Recursively collect parts of a selector expression."""
        if node.type == "identifier":
            parts.append(self._get_node_text(node) or "")
        elif node.type == "selector_expression":
            operand = node.child_by_field_name("operand")
            field_node = node.child_by_field_name("field")
            if operand:
                self._collect_selector_parts(operand, parts)
            if field_node:
                parts.append(self._get_node_text(field_node) or "")

    def _visit_short_var_declaration(self, node: Node) -> None:
        """Extract := short variable declarations."""
        # Get left side (variable names)
        left_node = node.child_by_field_name("left")
        right_node = node.child_by_field_name("right")

        if left_node is None:
            return

        # Handle expression_list on left side
        targets = []
        if left_node.type == "expression_list":
            for child in left_node.children:
                if child.type == "identifier":
                    targets.append(self._get_node_text(child))
        elif left_node.type == "identifier":
            targets.append(self._get_node_text(left_node))

        # Get values from right side
        values = []
        if right_node is not None:
            if right_node.type == "expression_list":
                for child in right_node.children:
                    if child.type not in (",",):
                        values.append(self._get_node_text(child))
            else:
                values.append(self._get_node_text(right_node))

        # Create assignment for each target
        for i, target in enumerate(targets):
            if target:
                value = values[i] if i < len(values) else ""
                assignment_info = GoAssignmentInfo(
                    target=target,
                    value=value or "",
                    line=node.start_point[0] + 1,
                    column=node.start_point[1],
                )
                self.assignments.append(assignment_info)

    def _visit_assignment_statement(self, node: Node) -> None:
        """Extract = assignment statements."""
        left_node = node.child_by_field_name("left")
        right_node = node.child_by_field_name("right")

        if left_node is None:
            return

        # Handle expression_list on left side
        targets = []
        if left_node.type == "expression_list":
            for child in left_node.children:
                if child.type == "identifier":
                    targets.append(self._get_node_text(child))
        elif left_node.type == "identifier":
            targets.append(self._get_node_text(left_node))

        # Get values from right side
        values = []
        if right_node is not None:
            if right_node.type == "expression_list":
                for child in right_node.children:
                    if child.type not in (",",):
                        values.append(self._get_node_text(child))
            else:
                values.append(self._get_node_text(right_node))

        # Create assignment for each target
        for i, target in enumerate(targets):
            if target:
                value = values[i] if i < len(values) else ""
                assignment_info = GoAssignmentInfo(
                    target=target,
                    value=value or "",
                    line=node.start_point[0] + 1,
                    column=node.start_point[1],
                )
                self.assignments.append(assignment_info)

    def _visit_interpreted_string_literal(self, node: Node) -> None:
        """Extract interpreted string literals ("strings")."""
        text = self._get_node_text(node)
        if text is None:
            return

        # Remove quotes
        value = text[1:-1] if len(text) >= 2 else text

        string_info = GoStringInfo(
            value=value,
            is_formatted=False,
            line=node.start_point[0] + 1,
            column=node.start_point[1],
        )
        self.strings.append(string_info)

    def _visit_raw_string_literal(self, node: Node) -> None:
        """Extract raw string literals (`raw strings`)."""
        text = self._get_node_text(node)
        if text is None:
            return

        # Remove backticks
        value = text[1:-1] if len(text) >= 2 else text

        string_info = GoStringInfo(
            value=value,
            is_formatted=False,
            line=node.start_point[0] + 1,
            column=node.start_point[1],
        )
        self.strings.append(string_info)

    def _visit_import_spec(self, node: Node) -> None:
        """Extract import paths."""
        path_node = node.child_by_field_name("path")
        if path_node is None:
            # Try to find string literal child
            for child in node.children:
                if child.type == "interpreted_string_literal":
                    path_node = child
                    break

        if path_node is not None:
            text = self._get_node_text(path_node)
            if text:
                # Remove quotes
                import_path = text.strip('"').strip('`')
                self.imports.append(import_path)

    def _get_node_text(self, node: Node) -> str | None:
        """Get the source text for a node."""
        if node is None:
            return None
        try:
            return self.source[node.start_byte:node.end_byte]
        except Exception:
            return None
