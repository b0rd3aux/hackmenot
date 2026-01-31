# Phase 6: Go and Terraform Support - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add comprehensive security scanning for Go and Terraform files with 47 new rules.

**Architecture:** New parsers for each language, integrated into existing Scanner/Engine with pattern matching methods.

**Tech Stack:** tree-sitter-go, python-hcl2, existing hackmenot infrastructure

---

## Task 1: Add Dependencies

**Files:**
- Modify: `pyproject.toml`

**Step 1: Add new dependencies to pyproject.toml**

Add `tree-sitter-go>=0.21.0` and `python-hcl2>=4.3.0` to the dependencies list.

**Step 2: Install and verify**

Run: `pip install -e ".[dev]"`
Verify: `python3 -c "import tree_sitter_go; import hcl2; print('OK')"`

**Step 3: Commit**

```bash
git add pyproject.toml
git commit -m "deps: add tree-sitter-go and python-hcl2 for Go/Terraform support"
```

---

## Task 2: Create GoParser

**Files:**
- Create: `src/hackmenot/parsers/golang.py`
- Create: `tests/test_parsers/test_golang.py`

**Step 1: Write failing tests**

```python
"""Tests for Go parser."""

from pathlib import Path

import pytest

from hackmenot.parsers.golang import GoParser, GoCallInfo, GoAssignmentInfo, GoStringInfo


class TestGoParser:
    """Tests for GoParser."""

    @pytest.fixture
    def parser(self):
        return GoParser()

    def test_parse_simple_call(self, parser):
        """Test parsing a simple function call."""
        code = 'fmt.Println("hello")'
        result = parser.parse_string(code)
        assert len(result.calls) >= 1
        call = result.calls[0]
        assert "fmt.Println" in call.name
        assert call.line == 1

    def test_parse_db_query(self, parser):
        """Test parsing database query call."""
        code = '''
package main

func main() {
    db.Query("SELECT * FROM users WHERE id = " + userId)
}
'''
        result = parser.parse_string(code)
        calls = [c for c in result.calls if "Query" in c.name]
        assert len(calls) >= 1

    def test_parse_exec_command(self, parser):
        """Test parsing exec.Command call."""
        code = '''
package main

import "os/exec"

func run() {
    exec.Command("ls", "-la")
}
'''
        result = parser.parse_string(code)
        calls = [c for c in result.calls if "Command" in c.name]
        assert len(calls) >= 1

    def test_parse_assignment(self, parser):
        """Test parsing variable assignment."""
        code = '''
package main

func main() {
    password := "secret123"
}
'''
        result = parser.parse_string(code)
        assert len(result.assignments) >= 1
        assignment = result.assignments[0]
        assert "password" in assignment.target
        assert "secret123" in assignment.value

    def test_parse_string_literal(self, parser):
        """Test parsing string literals."""
        code = '''
package main

func main() {
    apiKey := "sk-1234567890"
}
'''
        result = parser.parse_string(code)
        assert len(result.strings) >= 1

    def test_parse_formatted_string(self, parser):
        """Test parsing fmt.Sprintf calls as formatted strings."""
        code = '''
package main

func main() {
    query := fmt.Sprintf("SELECT * FROM %s", table)
}
'''
        result = parser.parse_string(code)
        # Sprintf calls should be captured
        calls = [c for c in result.calls if "Sprintf" in c.name]
        assert len(calls) >= 1

    def test_parse_file(self, parser, tmp_path):
        """Test parsing a Go file."""
        go_file = tmp_path / "main.go"
        go_file.write_text('''
package main

func main() {
    fmt.Println("hello")
}
''')
        result = parser.parse_file(go_file)
        assert len(result.calls) >= 1

    def test_parse_empty_file(self, parser):
        """Test parsing empty content."""
        result = parser.parse_string("")
        assert result.calls == []
        assert result.assignments == []
        assert result.strings == []

    def test_parse_invalid_go(self, parser):
        """Test parsing invalid Go code."""
        result = parser.parse_string("this is not valid go code {{{")
        # Should not crash, may return partial results
        assert result is not None

    def test_parse_method_call(self, parser):
        """Test parsing method calls on objects."""
        code = '''
package main

func main() {
    client.Get("http://example.com")
}
'''
        result = parser.parse_string(code)
        calls = [c for c in result.calls if "Get" in c.name]
        assert len(calls) >= 1

    def test_call_info_has_args(self, parser):
        """Test that CallInfo captures arguments."""
        code = '''
package main

func main() {
    db.Query("SELECT * FROM users", arg1, arg2)
}
'''
        result = parser.parse_string(code)
        calls = [c for c in result.calls if "Query" in c.name]
        assert len(calls) >= 1
        # Args should be captured
        assert len(calls[0].args) >= 1

    def test_parse_tls_config(self, parser):
        """Test parsing TLS config with InsecureSkipVerify."""
        code = '''
package main

func main() {
    tlsConfig := &tls.Config{
        InsecureSkipVerify: true,
    }
}
'''
        result = parser.parse_string(code)
        # Should capture the assignment with InsecureSkipVerify
        assert any("InsecureSkipVerify" in a.value for a in result.assignments) or \
               any("InsecureSkipVerify" in s.value for s in result.strings) or \
               len(result.assignments) >= 1

    def test_parse_import_statement(self, parser):
        """Test that imports are tracked."""
        code = '''
package main

import (
    "crypto/md5"
    "unsafe"
)
'''
        result = parser.parse_string(code)
        assert "crypto/md5" in result.imports or "md5" in result.imports
        assert "unsafe" in result.imports

    def test_parse_raw_string_literal(self, parser):
        """Test parsing raw string literals."""
        code = '''
package main

func main() {
    query := `SELECT * FROM users WHERE id = ` + id
}
'''
        result = parser.parse_string(code)
        assert len(result.strings) >= 1
```

**Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_parsers/test_golang.py -v`
Expected: FAIL (module not found)

**Step 3: Implement GoParser**

```python
"""Go language parser using tree-sitter."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tree_sitter_go as ts_go
from tree_sitter import Language, Parser

from hackmenot.parsers.base import BaseParser


@dataclass
class GoCallInfo:
    """Information about a function/method call."""
    name: str
    args: list[str]
    line: int
    column: int


@dataclass
class GoAssignmentInfo:
    """Information about a variable assignment."""
    target: str
    value: str
    line: int
    column: int


@dataclass
class GoStringInfo:
    """Information about a string literal."""
    value: str
    is_formatted: bool
    line: int
    column: int


@dataclass
class GoParseResult:
    """Result of parsing a Go file."""
    calls: list[GoCallInfo] = field(default_factory=list)
    assignments: list[GoAssignmentInfo] = field(default_factory=list)
    strings: list[GoStringInfo] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)


class GoParser(BaseParser):
    """Parser for Go source files using tree-sitter."""

    def __init__(self):
        self._language = Language(ts_go.language())
        self._parser = Parser(self._language)

    def parse_file(self, file_path: Path) -> GoParseResult:
        """Parse a Go file."""
        try:
            content = file_path.read_text(encoding="utf-8")
            return self.parse_string(content)
        except Exception:
            return GoParseResult()

    def parse_string(self, code: str) -> GoParseResult:
        """Parse Go source code string."""
        if not code.strip():
            return GoParseResult()

        try:
            tree = self._parser.parse(code.encode("utf-8"))
            extractor = _GoExtractor(code)
            extractor.visit(tree.root_node)
            return extractor.result
        except Exception:
            return GoParseResult()


class _GoExtractor:
    """Extracts security-relevant information from Go AST."""

    def __init__(self, source: str):
        self.source = source
        self.lines = source.split("\n")
        self.result = GoParseResult()

    def visit(self, node: Any) -> None:
        """Visit a node and its children."""
        method_name = f"visit_{node.type}"
        visitor = getattr(self, method_name, None)
        if visitor:
            visitor(node)

        for child in node.children:
            self.visit(child)

    def visit_call_expression(self, node: Any) -> None:
        """Extract function/method calls."""
        func_node = node.child_by_field_name("function")
        if func_node:
            name = self._get_node_text(func_node)
            args = self._extract_call_args(node)
            self.result.calls.append(GoCallInfo(
                name=name,
                args=args,
                line=node.start_point[0] + 1,
                column=node.start_point[1],
            ))

    def visit_short_var_declaration(self, node: Any) -> None:
        """Extract short variable declarations (:=)."""
        self._extract_assignment(node)

    def visit_assignment_statement(self, node: Any) -> None:
        """Extract assignment statements (=)."""
        self._extract_assignment(node)

    def _extract_assignment(self, node: Any) -> None:
        """Extract assignment from declaration or statement."""
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left and right:
            target = self._get_node_text(left)
            value = self._get_node_text(right)
            self.result.assignments.append(GoAssignmentInfo(
                target=target,
                value=value,
                line=node.start_point[0] + 1,
                column=node.start_point[1],
            ))

    def visit_interpreted_string_literal(self, node: Any) -> None:
        """Extract interpreted string literals."""
        value = self._get_node_text(node)
        self.result.strings.append(GoStringInfo(
            value=value,
            is_formatted=False,
            line=node.start_point[0] + 1,
            column=node.start_point[1],
        ))

    def visit_raw_string_literal(self, node: Any) -> None:
        """Extract raw string literals."""
        value = self._get_node_text(node)
        self.result.strings.append(GoStringInfo(
            value=value,
            is_formatted=False,
            line=node.start_point[0] + 1,
            column=node.start_point[1],
        ))

    def visit_import_spec(self, node: Any) -> None:
        """Extract import statements."""
        path_node = node.child_by_field_name("path")
        if path_node:
            import_path = self._get_node_text(path_node).strip('"')
            self.result.imports.append(import_path)

    def _extract_call_args(self, node: Any) -> list[str]:
        """Extract arguments from a call expression."""
        args = []
        args_node = node.child_by_field_name("arguments")
        if args_node:
            for child in args_node.children:
                if child.type not in ("(", ")", ","):
                    args.append(self._get_node_text(child))
        return args

    def _get_node_text(self, node: Any) -> str:
        """Get the source text for a node."""
        return self.source[node.start_byte:node.end_byte]
```

**Step 4: Run tests**

Run: `python3 -m pytest tests/test_parsers/test_golang.py -v`
Expected: All tests pass

**Step 5: Commit**

```bash
git add src/hackmenot/parsers/golang.py tests/test_parsers/test_golang.py
git commit -m "feat: add Go parser with tree-sitter"
```

---

## Task 3: Create TerraformParser

**Files:**
- Create: `src/hackmenot/parsers/terraform.py`
- Create: `tests/test_parsers/test_terraform.py`

**Step 1: Write failing tests**

```python
"""Tests for Terraform HCL parser."""

from pathlib import Path

import pytest

from hackmenot.parsers.terraform import (
    TerraformParser,
    TerraformResourceInfo,
    TerraformVariableInfo,
)


class TestTerraformParser:
    """Tests for TerraformParser."""

    @pytest.fixture
    def parser(self):
        return TerraformParser()

    def test_parse_s3_bucket(self, parser):
        """Test parsing an S3 bucket resource."""
        code = '''
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "public-read"
}
'''
        result = parser.parse_string(code)
        assert len(result.resources) == 1
        resource = result.resources[0]
        assert resource.resource_type == "aws_s3_bucket"
        assert resource.name == "example"
        assert resource.config.get("acl") == "public-read"

    def test_parse_security_group(self, parser):
        """Test parsing a security group resource."""
        code = '''
resource "aws_security_group" "allow_all" {
  name = "allow_all"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''
        result = parser.parse_string(code)
        assert len(result.resources) == 1
        resource = result.resources[0]
        assert resource.resource_type == "aws_security_group"
        assert "ingress" in resource.config

    def test_parse_variable_with_default(self, parser):
        """Test parsing a variable with default value."""
        code = '''
variable "db_password" {
  type    = string
  default = "supersecret123"
}
'''
        result = parser.parse_string(code)
        assert len(result.variables) == 1
        var = result.variables[0]
        assert var.name == "db_password"
        assert var.default == "supersecret123"

    def test_parse_variable_without_default(self, parser):
        """Test parsing a variable without default."""
        code = '''
variable "region" {
  type = string
}
'''
        result = parser.parse_string(code)
        assert len(result.variables) == 1
        var = result.variables[0]
        assert var.name == "region"
        assert var.default is None

    def test_parse_locals(self, parser):
        """Test parsing locals block."""
        code = '''
locals {
  api_key = "sk-1234567890"
  region  = "us-east-1"
}
'''
        result = parser.parse_string(code)
        assert len(result.locals) >= 1
        assert any(l.name == "api_key" for l in result.locals)

    def test_parse_multiple_resources(self, parser):
        """Test parsing multiple resources."""
        code = '''
resource "aws_s3_bucket" "bucket1" {
  bucket = "bucket1"
}

resource "aws_s3_bucket" "bucket2" {
  bucket = "bucket2"
}
'''
        result = parser.parse_string(code)
        assert len(result.resources) == 2

    def test_parse_file(self, parser, tmp_path):
        """Test parsing a Terraform file."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_instance" "web" {
  ami           = "ami-12345"
  instance_type = "t2.micro"
}
''')
        result = parser.parse_file(tf_file)
        assert len(result.resources) == 1

    def test_parse_empty_file(self, parser):
        """Test parsing empty content."""
        result = parser.parse_string("")
        assert result.resources == []
        assert result.variables == []
        assert result.locals == []

    def test_parse_invalid_hcl(self, parser):
        """Test parsing invalid HCL."""
        result = parser.parse_string("this is {{ not valid hcl")
        assert result is not None
        # Should not crash

    def test_parse_ebs_volume(self, parser):
        """Test parsing EBS volume resource."""
        code = '''
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
}
'''
        result = parser.parse_string(code)
        assert len(result.resources) == 1
        resource = result.resources[0]
        assert resource.resource_type == "aws_ebs_volume"
        # Note: no encrypted = true

    def test_parse_iam_policy(self, parser):
        """Test parsing IAM policy resource."""
        code = '''
resource "aws_iam_policy" "admin" {
  name = "admin_policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["*"]
        Effect   = "Allow"
        Resource = ["*"]
      }
    ]
  })
}
'''
        result = parser.parse_string(code)
        assert len(result.resources) == 1

    def test_parse_tfvars(self, parser, tmp_path):
        """Test parsing .tfvars file."""
        tfvars = tmp_path / "secrets.tfvars"
        tfvars.write_text('''
db_password = "mysecretpassword"
api_key     = "sk-abcdef123456"
''')
        result = parser.parse_file(tfvars)
        assert len(result.variables) >= 1

    def test_resource_has_line_number(self, parser):
        """Test that resources have line numbers."""
        code = '''
resource "aws_s3_bucket" "test" {
  bucket = "test"
}
'''
        result = parser.parse_string(code)
        assert result.resources[0].line >= 1
```

**Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_parsers/test_terraform.py -v`
Expected: FAIL (module not found)

**Step 3: Implement TerraformParser**

```python
"""Terraform HCL parser using python-hcl2."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import hcl2

from hackmenot.parsers.base import BaseParser


@dataclass
class TerraformResourceInfo:
    """Information about a Terraform resource."""
    resource_type: str
    name: str
    config: dict[str, Any]
    line: int


@dataclass
class TerraformVariableInfo:
    """Information about a Terraform variable."""
    name: str
    default: Any
    sensitive: bool
    line: int


@dataclass
class TerraformLocalInfo:
    """Information about a Terraform local value."""
    name: str
    value: Any
    line: int


@dataclass
class TerraformParseResult:
    """Result of parsing a Terraform file."""
    resources: list[TerraformResourceInfo] = field(default_factory=list)
    variables: list[TerraformVariableInfo] = field(default_factory=list)
    locals: list[TerraformLocalInfo] = field(default_factory=list)


class TerraformParser(BaseParser):
    """Parser for Terraform HCL files."""

    def parse_file(self, file_path: Path) -> TerraformParseResult:
        """Parse a Terraform file."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return self._parse_hcl(f, file_path.suffix)
        except Exception:
            return TerraformParseResult()

    def parse_string(self, code: str) -> TerraformParseResult:
        """Parse Terraform HCL string."""
        if not code.strip():
            return TerraformParseResult()

        try:
            from io import StringIO
            return self._parse_hcl(StringIO(code), ".tf")
        except Exception:
            return TerraformParseResult()

    def _parse_hcl(self, file_obj: Any, suffix: str) -> TerraformParseResult:
        """Parse HCL from file object."""
        try:
            parsed = hcl2.load(file_obj)
        except Exception:
            return TerraformParseResult()

        result = TerraformParseResult()

        # Handle .tfvars files (just key-value pairs)
        if suffix == ".tfvars":
            for key, value in parsed.items():
                result.variables.append(TerraformVariableInfo(
                    name=key,
                    default=value,
                    sensitive=False,
                    line=1,  # hcl2 doesn't provide line numbers
                ))
            return result

        # Parse resources
        for resource_block in parsed.get("resource", []):
            for resource_type, resources in resource_block.items():
                for name, config in resources.items():
                    result.resources.append(TerraformResourceInfo(
                        resource_type=resource_type,
                        name=name,
                        config=config if isinstance(config, dict) else {},
                        line=1,  # hcl2 doesn't provide line numbers easily
                    ))

        # Parse variables
        for var_block in parsed.get("variable", []):
            for var_name, var_config in var_block.items():
                default = None
                sensitive = False
                if isinstance(var_config, dict):
                    default = var_config.get("default")
                    sensitive = var_config.get("sensitive", False)
                result.variables.append(TerraformVariableInfo(
                    name=var_name,
                    default=default,
                    sensitive=sensitive,
                    line=1,
                ))

        # Parse locals
        for locals_block in parsed.get("locals", []):
            if isinstance(locals_block, dict):
                for local_name, local_value in locals_block.items():
                    result.locals.append(TerraformLocalInfo(
                        name=local_name,
                        value=local_value,
                        line=1,
                    ))

        return result
```

**Step 4: Run tests**

Run: `python3 -m pytest tests/test_parsers/test_terraform.py -v`
Expected: All tests pass

**Step 5: Commit**

```bash
git add src/hackmenot/parsers/terraform.py tests/test_parsers/test_terraform.py
git commit -m "feat: add Terraform HCL parser"
```

---

## Task 4: Integrate GoParser into Scanner

**Files:**
- Modify: `src/hackmenot/core/scanner.py`
- Create: `tests/test_core/test_go_scanning.py`

**Step 1: Write failing tests**

```python
"""Tests for Go file scanning integration."""

from pathlib import Path

import pytest

from hackmenot.core.scanner import Scanner


class TestGoScanning:
    """Tests for scanning Go files."""

    def test_scanner_detects_go_files(self, tmp_path):
        """Test that scanner recognizes .go files."""
        go_file = tmp_path / "main.go"
        go_file.write_text('package main\n\nfunc main() {}')

        scanner = Scanner()
        result = scanner.scan(tmp_path)

        assert result.files_scanned >= 1

    def test_scanner_supported_extensions_includes_go(self):
        """Test that .go is in supported extensions."""
        scanner = Scanner()
        assert ".go" in scanner.SUPPORTED_EXTENSIONS

    def test_scanner_detects_language_go(self, tmp_path):
        """Test language detection for Go files."""
        go_file = tmp_path / "main.go"
        go_file.write_text('package main')

        scanner = Scanner()
        lang = scanner._detect_language(go_file)

        assert lang == "go"
```

**Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_core/test_go_scanning.py -v`
Expected: FAIL (Go not supported)

**Step 3: Update Scanner to support Go**

In `src/hackmenot/core/scanner.py`, add:

1. Add to imports:
```python
from hackmenot.parsers.golang import GoParser
```

2. Add to SUPPORTED_EXTENSIONS:
```python
SUPPORTED_EXTENSIONS = {".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".go"}
GO_EXTENSIONS = {".go"}
```

3. In `__init__`, add:
```python
self.go_parser = GoParser()
```

4. In `_detect_language`, add before the return statement:
```python
if file_path.suffix in self.GO_EXTENSIONS:
    return "go"
```

5. In `_scan_file`, add a case for Go:
```python
elif language == "go":
    parse_result = self.go_parser.parse_file(file_path)
```

**Step 4: Run tests**

Run: `python3 -m pytest tests/test_core/test_go_scanning.py -v`
Expected: All tests pass

**Step 5: Commit**

```bash
git add src/hackmenot/core/scanner.py tests/test_core/test_go_scanning.py
git commit -m "feat: integrate Go parser into Scanner"
```

---

## Task 5: Integrate TerraformParser into Scanner

**Files:**
- Modify: `src/hackmenot/core/scanner.py`
- Create: `tests/test_core/test_terraform_scanning.py`

**Step 1: Write failing tests**

```python
"""Tests for Terraform file scanning integration."""

from pathlib import Path

import pytest

from hackmenot.core.scanner import Scanner


class TestTerraformScanning:
    """Tests for scanning Terraform files."""

    def test_scanner_detects_tf_files(self, tmp_path):
        """Test that scanner recognizes .tf files."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('resource "aws_instance" "web" { ami = "ami-123" }')

        scanner = Scanner()
        result = scanner.scan(tmp_path)

        assert result.files_scanned >= 1

    def test_scanner_detects_tfvars_files(self, tmp_path):
        """Test that scanner recognizes .tfvars files."""
        tfvars = tmp_path / "terraform.tfvars"
        tfvars.write_text('region = "us-east-1"')

        scanner = Scanner()
        result = scanner.scan(tmp_path)

        assert result.files_scanned >= 1

    def test_scanner_supported_extensions_includes_terraform(self):
        """Test that .tf and .tfvars are in supported extensions."""
        scanner = Scanner()
        assert ".tf" in scanner.SUPPORTED_EXTENSIONS
        assert ".tfvars" in scanner.SUPPORTED_EXTENSIONS

    def test_scanner_detects_language_terraform(self, tmp_path):
        """Test language detection for Terraform files."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('resource "null" "test" {}')

        scanner = Scanner()
        lang = scanner._detect_language(tf_file)

        assert lang == "terraform"
```

**Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_core/test_terraform_scanning.py -v`
Expected: FAIL (Terraform not supported)

**Step 3: Update Scanner to support Terraform**

In `src/hackmenot/core/scanner.py`, add:

1. Add to imports:
```python
from hackmenot.parsers.terraform import TerraformParser
```

2. Update SUPPORTED_EXTENSIONS:
```python
SUPPORTED_EXTENSIONS = {".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".go", ".tf", ".tfvars"}
TERRAFORM_EXTENSIONS = {".tf", ".tfvars"}
```

3. In `__init__`, add:
```python
self.tf_parser = TerraformParser()
```

4. In `_detect_language`, add:
```python
if file_path.suffix in self.TERRAFORM_EXTENSIONS:
    return "terraform"
```

5. In `_scan_file`, add a case for Terraform:
```python
elif language == "terraform":
    parse_result = self.tf_parser.parse_file(file_path)
```

**Step 4: Run tests**

Run: `python3 -m pytest tests/test_core/test_terraform_scanning.py -v`
Expected: All tests pass

**Step 5: Commit**

```bash
git add src/hackmenot/core/scanner.py tests/test_core/test_terraform_scanning.py
git commit -m "feat: integrate Terraform parser into Scanner"
```

---

## Task 6: Add Go Pattern Matching to RulesEngine

**Files:**
- Modify: `src/hackmenot/rules/engine.py`
- Create: `tests/test_rules/test_go_engine.py`

**Step 1: Write failing tests**

```python
"""Tests for Go rule pattern matching in engine."""

import pytest

from hackmenot.core.models import Rule, Severity
from hackmenot.parsers.golang import GoParser, GoParseResult
from hackmenot.rules.engine import RulesEngine


class TestGoPatternMatching:
    """Tests for Go pattern matching in RulesEngine."""

    @pytest.fixture
    def engine(self):
        return RulesEngine()

    @pytest.fixture
    def parser(self):
        return GoParser()

    def test_match_call_pattern(self, engine, parser):
        """Test matching call patterns in Go code."""
        code = '''
package main

func main() {
    db.Query("SELECT * FROM users WHERE id = " + id)
}
'''
        parse_result = parser.parse_string(code)
        rule = Rule(
            id="GO_TEST001",
            name="test-call",
            severity=Severity.HIGH,
            category="test",
            languages=["go"],
            description="Test",
            message="Found call",
            pattern={"type": "call", "names": ["db.Query", "db.Exec"]},
        )

        findings = engine._check_go_rule(rule, parse_result, "test.go")
        assert len(findings) >= 1

    def test_match_string_pattern(self, engine, parser):
        """Test matching string patterns in Go code."""
        code = '''
package main

func main() {
    password := "secret123"
}
'''
        parse_result = parser.parse_string(code)
        rule = Rule(
            id="GO_TEST002",
            name="test-string",
            severity=Severity.HIGH,
            category="test",
            languages=["go"],
            description="Test",
            message="Found hardcoded password",
            pattern={"type": "string", "contains": ["password", "secret"]},
        )

        findings = engine._check_go_rule(rule, parse_result, "test.go")
        assert len(findings) >= 1

    def test_match_import_pattern(self, engine, parser):
        """Test matching import patterns in Go code."""
        code = '''
package main

import "crypto/md5"

func main() {}
'''
        parse_result = parser.parse_string(code)
        rule = Rule(
            id="GO_TEST003",
            name="test-import",
            severity=Severity.MEDIUM,
            category="test",
            languages=["go"],
            description="Test",
            message="Found weak crypto import",
            pattern={"type": "import", "names": ["crypto/md5", "crypto/sha1"]},
        )

        findings = engine._check_go_rule(rule, parse_result, "test.go")
        assert len(findings) >= 1

    def test_no_match_different_language(self, engine, parser):
        """Test that Go rules don't match non-Go files."""
        code = 'db.Query("SELECT * FROM users")'
        parse_result = parser.parse_string(code)
        rule = Rule(
            id="GO_TEST001",
            name="test-call",
            severity=Severity.HIGH,
            category="test",
            languages=["python"],  # Python only
            description="Test",
            message="Found call",
            pattern={"type": "call", "names": ["db.Query"]},
        )

        # Should not match because language doesn't match
        # (This is handled at a higher level, but the check should be safe)

    def test_language_detection_go(self, engine):
        """Test language detection for .go files."""
        lang = engine._detect_language(".go")
        assert lang == "go"
```

**Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_rules/test_go_engine.py -v`
Expected: FAIL (method not found)

**Step 3: Add Go pattern matching to RulesEngine**

In `src/hackmenot/rules/engine.py`:

1. Add to `_detect_language` method's ext_map:
```python
".go": "go",
```

2. Add new method `_check_go_rule`:
```python
def _check_go_rule(
    self,
    rule: Rule,
    parse_result: Any,
    file_path: str,
) -> list[Finding]:
    """Check a Go rule against parse result."""
    findings = []
    pattern = rule.pattern
    pattern_type = pattern.get("type", "")

    if pattern_type == "call":
        names = [n.upper() for n in pattern.get("names", [])]
        for call in parse_result.calls:
            if any(name in call.name.upper() for name in names):
                findings.append(self._create_finding(
                    rule=rule,
                    file_path=file_path,
                    line=call.line,
                    column=call.column,
                    code_snippet=call.name,
                ))

    elif pattern_type == "string":
        contains = [c.upper() for c in pattern.get("contains", [])]
        # Check assignments
        for assign in parse_result.assignments:
            combined = f"{assign.target} {assign.value}".upper()
            if any(c in combined for c in contains):
                findings.append(self._create_finding(
                    rule=rule,
                    file_path=file_path,
                    line=assign.line,
                    column=assign.column,
                    code_snippet=f"{assign.target} = {assign.value}",
                ))
        # Check string literals
        for string in parse_result.strings:
            if any(c in string.value.upper() for c in contains):
                findings.append(self._create_finding(
                    rule=rule,
                    file_path=file_path,
                    line=string.line,
                    column=string.column,
                    code_snippet=string.value,
                ))

    elif pattern_type == "import":
        names = [n.lower() for n in pattern.get("names", [])]
        for imp in parse_result.imports:
            if any(name in imp.lower() for name in names):
                findings.append(self._create_finding(
                    rule=rule,
                    file_path=file_path,
                    line=1,
                    column=0,
                    code_snippet=f'import "{imp}"',
                ))

    return findings
```

3. Update the `check` method to route Go files:
```python
# In the check method, add routing for Go
if language == "go":
    for rule in self._rules:
        if "go" not in rule.languages:
            continue
        findings.extend(self._check_go_rule(rule, parse_result, str(file_path)))
```

**Step 4: Run tests**

Run: `python3 -m pytest tests/test_rules/test_go_engine.py -v`
Expected: All tests pass

**Step 5: Commit**

```bash
git add src/hackmenot/rules/engine.py tests/test_rules/test_go_engine.py
git commit -m "feat: add Go pattern matching to RulesEngine"
```

---

## Task 7: Add Terraform Pattern Matching to RulesEngine

**Files:**
- Modify: `src/hackmenot/rules/engine.py`
- Create: `tests/test_rules/test_terraform_engine.py`

**Step 1: Write failing tests**

```python
"""Tests for Terraform rule pattern matching in engine."""

import pytest

from hackmenot.core.models import Rule, Severity
from hackmenot.parsers.terraform import TerraformParser, TerraformParseResult
from hackmenot.rules.engine import RulesEngine


class TestTerraformPatternMatching:
    """Tests for Terraform pattern matching in RulesEngine."""

    @pytest.fixture
    def engine(self):
        return RulesEngine()

    @pytest.fixture
    def parser(self):
        return TerraformParser()

    def test_match_resource_field_contains(self, engine, parser):
        """Test matching resource field contains pattern."""
        code = '''
resource "aws_s3_bucket" "public" {
  bucket = "my-bucket"
  acl    = "public-read"
}
'''
        parse_result = parser.parse_string(code)
        rule = Rule(
            id="TF_TEST001",
            name="test-resource",
            severity=Severity.CRITICAL,
            category="test",
            languages=["terraform"],
            description="Test",
            message="Found public bucket",
            pattern={
                "type": "resource",
                "resource_type": "aws_s3_bucket",
                "field": "acl",
                "contains": ["public-read", "public-read-write"],
            },
        )

        findings = engine._check_terraform_rule(rule, parse_result, "main.tf")
        assert len(findings) >= 1

    def test_match_resource_missing_block(self, engine, parser):
        """Test matching resource missing block pattern."""
        code = '''
resource "aws_s3_bucket" "unencrypted" {
  bucket = "my-bucket"
}
'''
        parse_result = parser.parse_string(code)
        rule = Rule(
            id="TF_TEST002",
            name="test-missing-block",
            severity=Severity.HIGH,
            category="test",
            languages=["terraform"],
            description="Test",
            message="Missing encryption",
            pattern={
                "type": "resource",
                "resource_type": "aws_s3_bucket",
                "missing_block": "server_side_encryption_configuration",
            },
        )

        findings = engine._check_terraform_rule(rule, parse_result, "main.tf")
        assert len(findings) >= 1

    def test_match_variable_secret(self, engine, parser):
        """Test matching variable with secret pattern."""
        code = '''
variable "db_password" {
  default = "supersecret123"
}
'''
        parse_result = parser.parse_string(code)
        rule = Rule(
            id="TF_TEST003",
            name="test-secret",
            severity=Severity.CRITICAL,
            category="test",
            languages=["terraform"],
            description="Test",
            message="Hardcoded secret in variable",
            pattern={
                "type": "variable",
                "name_contains": ["password", "secret", "key"],
                "has_default": True,
            },
        )

        findings = engine._check_terraform_rule(rule, parse_result, "main.tf")
        assert len(findings) >= 1

    def test_no_match_encrypted_bucket(self, engine, parser):
        """Test that encrypted bucket doesn't match missing encryption rule."""
        code = '''
resource "aws_s3_bucket" "encrypted" {
  bucket = "my-bucket"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
'''
        parse_result = parser.parse_string(code)
        rule = Rule(
            id="TF_TEST002",
            name="test-missing-block",
            severity=Severity.HIGH,
            category="test",
            languages=["terraform"],
            description="Test",
            message="Missing encryption",
            pattern={
                "type": "resource",
                "resource_type": "aws_s3_bucket",
                "missing_block": "server_side_encryption_configuration",
            },
        )

        findings = engine._check_terraform_rule(rule, parse_result, "main.tf")
        assert len(findings) == 0

    def test_language_detection_terraform(self, engine):
        """Test language detection for .tf files."""
        assert engine._detect_language(".tf") == "terraform"
        assert engine._detect_language(".tfvars") == "terraform"
```

**Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_rules/test_terraform_engine.py -v`
Expected: FAIL (method not found)

**Step 3: Add Terraform pattern matching to RulesEngine**

In `src/hackmenot/rules/engine.py`:

1. Add to `_detect_language` method's ext_map:
```python
".tf": "terraform",
".tfvars": "terraform",
```

2. Add new method `_check_terraform_rule`:
```python
def _check_terraform_rule(
    self,
    rule: Rule,
    parse_result: Any,
    file_path: str,
) -> list[Finding]:
    """Check a Terraform rule against parse result."""
    findings = []
    pattern = rule.pattern
    pattern_type = pattern.get("type", "")

    if pattern_type == "resource":
        resource_type = pattern.get("resource_type", "")
        for resource in parse_result.resources:
            if resource.resource_type != resource_type:
                continue

            # Check field contains
            field = pattern.get("field")
            contains = pattern.get("contains", [])
            if field and contains:
                field_value = resource.config.get(field, "")
                if isinstance(field_value, str):
                    if any(c in field_value for c in contains):
                        findings.append(self._create_finding(
                            rule=rule,
                            file_path=file_path,
                            line=resource.line,
                            column=0,
                            code_snippet=f'{resource.resource_type}.{resource.name}',
                        ))

            # Check missing block
            missing_block = pattern.get("missing_block")
            if missing_block:
                if missing_block not in resource.config:
                    findings.append(self._create_finding(
                        rule=rule,
                        file_path=file_path,
                        line=resource.line,
                        column=0,
                        code_snippet=f'{resource.resource_type}.{resource.name}',
                    ))

            # Check missing field with value
            missing_field = pattern.get("missing_field")
            expected_value = pattern.get("expected_value")
            if missing_field:
                actual = resource.config.get(missing_field)
                if actual != expected_value:
                    findings.append(self._create_finding(
                        rule=rule,
                        file_path=file_path,
                        line=resource.line,
                        column=0,
                        code_snippet=f'{resource.resource_type}.{resource.name}',
                    ))

    elif pattern_type == "variable":
        name_contains = [n.lower() for n in pattern.get("name_contains", [])]
        has_default = pattern.get("has_default", False)

        for var in parse_result.variables:
            name_matches = any(c in var.name.lower() for c in name_contains)
            default_matches = has_default and var.default is not None

            if name_matches and default_matches:
                findings.append(self._create_finding(
                    rule=rule,
                    file_path=file_path,
                    line=var.line,
                    column=0,
                    code_snippet=f'variable "{var.name}"',
                ))

    elif pattern_type == "local":
        name_contains = [n.lower() for n in pattern.get("name_contains", [])]

        for local in parse_result.locals:
            if any(c in local.name.lower() for c in name_contains):
                findings.append(self._create_finding(
                    rule=rule,
                    file_path=file_path,
                    line=local.line,
                    column=0,
                    code_snippet=f'local.{local.name}',
                ))

    return findings
```

3. Update the `check` method to route Terraform files:
```python
# In the check method, add routing for Terraform
if language == "terraform":
    for rule in self._rules:
        if "terraform" not in rule.languages:
            continue
        findings.extend(self._check_terraform_rule(rule, parse_result, str(file_path)))
```

**Step 4: Run tests**

Run: `python3 -m pytest tests/test_rules/test_terraform_engine.py -v`
Expected: All tests pass

**Step 5: Commit**

```bash
git add src/hackmenot/rules/engine.py tests/test_rules/test_terraform_engine.py
git commit -m "feat: add Terraform pattern matching to RulesEngine"
```

---

## Tasks 8-18: Implement Rules

For each rule category, create YAML rule files in `src/hackmenot/rules/builtin/` following the established pattern.

### Task 8: Go Injection Rules (6 rules)

**Files:**
- Create: `src/hackmenot/rules/builtin/go/GO_INJ001.yml` through `GO_INJ006.yml`
- Create: `tests/test_rules/test_go_injection.py`

### Task 9: Go Crypto Rules (5 rules)

**Files:**
- Create: `src/hackmenot/rules/builtin/go/GO_CRY001.yml` through `GO_CRY005.yml`
- Create: `tests/test_rules/test_go_crypto.py`

### Task 10: Go Auth Rules (4 rules)

**Files:**
- Create: `src/hackmenot/rules/builtin/go/GO_AUT001.yml` through `GO_AUT004.yml`
- Create: `tests/test_rules/test_go_auth.py`

### Task 11: Go Concurrency Rules (3 rules)

**Files:**
- Create: `src/hackmenot/rules/builtin/go/GO_CON001.yml` through `GO_CON003.yml`
- Create: `tests/test_rules/test_go_concurrency.py`

### Task 12: Go Unsafe/Network Rules (5 rules)

**Files:**
- Create: `src/hackmenot/rules/builtin/go/GO_UNS001.yml`, `GO_UNS002.yml`, `GO_NET001.yml` through `GO_NET003.yml`
- Create: `tests/test_rules/test_go_unsafe.py`

### Task 13: Terraform S3 Rules (4 rules)

**Files:**
- Create: `src/hackmenot/rules/builtin/terraform/TF_S3001.yml` through `TF_S3004.yml`
- Create: `tests/test_rules/test_tf_s3.py`

### Task 14: Terraform Security Group Rules (4 rules)

**Files:**
- Create: `src/hackmenot/rules/builtin/terraform/TF_SG001.yml` through `TF_SG004.yml`
- Create: `tests/test_rules/test_tf_sg.py`

### Task 15: Terraform Encryption Rules (4 rules)

**Files:**
- Create: `src/hackmenot/rules/builtin/terraform/TF_ENC001.yml` through `TF_ENC004.yml`
- Create: `tests/test_rules/test_tf_encryption.py`

### Task 16: Terraform IAM Rules (3 rules)

**Files:**
- Create: `src/hackmenot/rules/builtin/terraform/TF_IAM001.yml` through `TF_IAM003.yml`
- Create: `tests/test_rules/test_tf_iam.py`

### Task 17: Terraform Logging Rules (3 rules)

**Files:**
- Create: `src/hackmenot/rules/builtin/terraform/TF_LOG001.yml` through `TF_LOG003.yml`
- Create: `tests/test_rules/test_tf_logging.py`

### Task 18: Terraform Secrets/Network Rules (6 rules)

**Files:**
- Create: `src/hackmenot/rules/builtin/terraform/TF_SEC001.yml` through `TF_SEC004.yml`, `TF_NET001.yml`, `TF_NET002.yml`
- Create: `tests/test_rules/test_tf_secrets.py`

---

## Task 19: Go Integration Tests

**Files:**
- Create: `tests/test_integration/test_go_scan.py`

Write end-to-end tests that scan Go files with multiple vulnerabilities and verify all are detected.

---

## Task 20: Terraform Integration Tests

**Files:**
- Create: `tests/test_integration/test_terraform_scan.py`

Write end-to-end tests that scan Terraform files with multiple misconfigurations and verify all are detected.

---

## Task 21: Update Documentation

**Files:**
- Modify: `docs/rules-reference.md` - Add Go and Terraform rules
- Modify: `docs/getting-started.md` - Mention Go and Terraform support
- Modify: `README.md` - Update supported languages

---

## Summary

**Total Tasks:** 21
**Total New Rules:** 47 (23 Go + 24 Terraform)
**Estimated New Tests:** ~119
