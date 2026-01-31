"""JavaScript/TypeScript parser using tree-sitter."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tree_sitter_javascript as ts_javascript
from tree_sitter import Language, Parser, Node


@dataclass
class CallInfo:
    """Information about a function/method call."""

    name: str
    line_number: int
    column: int
    arguments: list[str] = field(default_factory=list)
    is_method_call: bool = False


@dataclass
class TemplateLiteralInfo:
    """Information about a template literal string."""

    value: str
    line_number: int
    column: int
    expressions: list[str] = field(default_factory=list)


@dataclass
class AssignmentInfo:
    """Information about a variable assignment."""

    name: str
    line_number: int
    column: int
    value_type: str = "unknown"
    value: str | None = None


@dataclass
class JSXElementInfo:
    """Information about a JSX element."""

    name: str
    line_number: int
    column: int
    attributes: list[str] = field(default_factory=list)
    is_self_closing: bool = False


@dataclass
class JSParseResult:
    """Result of parsing a JavaScript/TypeScript file."""

    file_path: Path
    has_error: bool = False
    error_message: str | None = None
    _calls: list[CallInfo] = field(default_factory=list)
    _template_literals: list[TemplateLiteralInfo] = field(default_factory=list)
    _assignments: list[AssignmentInfo] = field(default_factory=list)
    _jsx_elements: list[JSXElementInfo] = field(default_factory=list)
    _raw_tree: Any = None

    def get_calls(self) -> list[CallInfo]:
        """Get all function/method calls."""
        return self._calls

    def get_template_literals(self) -> list[TemplateLiteralInfo]:
        """Get all template literals."""
        return self._template_literals

    def get_assignments(self) -> list[AssignmentInfo]:
        """Get all variable assignments."""
        return self._assignments

    def get_jsx_elements(self) -> list[JSXElementInfo]:
        """Get all JSX elements."""
        return self._jsx_elements


class JavaScriptParser:
    """Parser for JavaScript/TypeScript source files using tree-sitter."""

    SUPPORTED_EXTENSIONS = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}

    def __init__(self) -> None:
        """Initialize the parser with tree-sitter JavaScript language."""
        self._language = Language(ts_javascript.language())
        self._parser = Parser(self._language)

    def parse_file(self, file_path: Path) -> JSParseResult:
        """Parse a JavaScript/TypeScript file."""
        try:
            source = file_path.read_text(encoding="utf-8")
            return self.parse_string(source, str(file_path))
        except FileNotFoundError as e:
            return JSParseResult(
                file_path=file_path,
                has_error=True,
                error_message=f"File not found: {e}",
            )
        except Exception as e:
            return JSParseResult(
                file_path=file_path,
                has_error=True,
                error_message=str(e),
            )

    def parse_string(self, source: str, filename: str = "<string>") -> JSParseResult:
        """Parse JavaScript/TypeScript source code string."""
        file_path = Path(filename)

        tree = self._parser.parse(bytes(source, "utf-8"))

        extractor = _PatternExtractor(source)
        extractor.walk(tree.root_node)

        return JSParseResult(
            file_path=file_path,
            _calls=extractor.calls,
            _template_literals=extractor.template_literals,
            _assignments=extractor.assignments,
            _jsx_elements=extractor.jsx_elements,
            _raw_tree=tree,
        )


class _PatternExtractor:
    """Walks the AST and extracts security-relevant patterns."""

    def __init__(self, source: str) -> None:
        self.source = source
        self.calls: list[CallInfo] = []
        self.template_literals: list[TemplateLiteralInfo] = []
        self.assignments: list[AssignmentInfo] = []
        self.jsx_elements: list[JSXElementInfo] = []

    def walk(self, node: Node) -> None:
        """Walk the AST tree and extract patterns."""
        self._visit(node)

    def _visit(self, node: Node) -> None:
        """Visit a node and dispatch to the appropriate handler."""
        if node.type == "call_expression":
            self._extract_call(node)
        elif node.type == "template_string":
            self._extract_template_literal(node)
        elif node.type in ("variable_declarator", "assignment_expression"):
            self._extract_assignment(node)
        elif node.type in ("jsx_element", "jsx_self_closing_element"):
            self._extract_jsx(node)

        # Continue walking children
        for child in node.children:
            self._visit(child)

    def _extract_call(self, node: Node) -> None:
        """Extract function/method call information."""
        # Get the function being called
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

        is_method = function_node.type == "member_expression"

        call_info = CallInfo(
            name=name,
            line_number=node.start_point[0] + 1,  # 1-indexed
            column=node.start_point[1],
            arguments=arguments,
            is_method_call=is_method,
        )
        self.calls.append(call_info)

    def _get_call_name(self, node: Node) -> str | None:
        """Get the name of a function being called."""
        if node.type == "identifier":
            return self._get_node_text(node)
        elif node.type == "member_expression":
            # Handle cases like obj.method, obj.prop.method, etc.
            parts = []
            self._collect_member_parts(node, parts)
            return ".".join(parts) if parts else None
        return None

    def _collect_member_parts(self, node: Node, parts: list[str]) -> None:
        """Recursively collect parts of a member expression."""
        if node.type == "identifier":
            parts.append(self._get_node_text(node) or "")
        elif node.type == "member_expression":
            obj = node.child_by_field_name("object")
            prop = node.child_by_field_name("property")
            if obj:
                self._collect_member_parts(obj, parts)
            if prop:
                parts.append(self._get_node_text(prop) or "")

    def _extract_template_literal(self, node: Node) -> None:
        """Extract template literal information."""
        # Reconstruct the template string value
        parts = []
        expressions = []

        for child in node.children:
            if child.type == "string_fragment":
                parts.append(self._get_node_text(child) or "")
            elif child.type == "template_substitution":
                # Get the expression inside ${}
                for subchild in child.children:
                    if subchild.type not in ("${", "}"):
                        expr_text = self._get_node_text(subchild)
                        if expr_text:
                            expressions.append(expr_text)
                            parts.append(f"${{{expr_text}}}")

        value = "".join(parts)

        template_info = TemplateLiteralInfo(
            value=value,
            line_number=node.start_point[0] + 1,
            column=node.start_point[1],
            expressions=expressions,
        )
        self.template_literals.append(template_info)

    def _extract_assignment(self, node: Node) -> None:
        """Extract variable assignment information."""
        if node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")
        else:  # assignment_expression
            name_node = node.child_by_field_name("left")
            value_node = node.child_by_field_name("right")

        if name_node is None:
            return

        name = self._get_node_text(name_node)
        if name is None:
            return

        value_type = "unknown"
        value = None

        if value_node is not None:
            value = self._get_node_text(value_node)
            value_type = self._infer_value_type(value_node)

        assignment_info = AssignmentInfo(
            name=name,
            line_number=node.start_point[0] + 1,
            column=node.start_point[1],
            value_type=value_type,
            value=value,
        )
        self.assignments.append(assignment_info)

    def _infer_value_type(self, node: Node) -> str:
        """Infer the type of a value node."""
        type_map = {
            "string": "string",
            "template_string": "template_string",
            "number": "number",
            "true": "boolean",
            "false": "boolean",
            "null": "null",
            "undefined": "undefined",
            "array": "array",
            "object": "object",
            "arrow_function": "function",
            "function_expression": "function",
            "call_expression": "call",
            "member_expression": "member_access",
        }
        return type_map.get(node.type, "unknown")

    def _extract_jsx(self, node: Node) -> None:
        """Extract JSX element information."""
        is_self_closing = node.type == "jsx_self_closing_element"

        # Get element name
        name = None
        attributes = []

        for child in node.children:
            if child.type in ("jsx_opening_element", "identifier"):
                if child.type == "identifier":
                    name = self._get_node_text(child)
                else:
                    # jsx_opening_element
                    for subchild in child.children:
                        if subchild.type == "identifier":
                            name = self._get_node_text(subchild)
                        elif subchild.type == "jsx_attribute":
                            attr_text = self._get_node_text(subchild)
                            if attr_text:
                                attributes.append(attr_text)

            elif child.type == "jsx_attribute" and is_self_closing:
                attr_text = self._get_node_text(child)
                if attr_text:
                    attributes.append(attr_text)

        # For self-closing, name is direct child
        if is_self_closing and name is None:
            for child in node.children:
                if child.type == "identifier":
                    name = self._get_node_text(child)
                    break

        if name is None:
            return

        jsx_info = JSXElementInfo(
            name=name,
            line_number=node.start_point[0] + 1,
            column=node.start_point[1],
            attributes=attributes,
            is_self_closing=is_self_closing,
        )
        self.jsx_elements.append(jsx_info)

    def _get_node_text(self, node: Node) -> str | None:
        """Get the source text for a node."""
        if node is None:
            return None
        try:
            return self.source[node.start_byte:node.end_byte]
        except Exception:
            return None
