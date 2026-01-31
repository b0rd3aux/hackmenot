"""Tests for Terraform pattern matching in the RulesEngine."""

from pathlib import Path

import pytest

from hackmenot.core.models import Rule, Severity
from hackmenot.parsers.terraform import TerraformParser
from hackmenot.rules.engine import RulesEngine


@pytest.fixture
def engine() -> RulesEngine:
    """Create a RulesEngine instance."""
    return RulesEngine()


@pytest.fixture
def parser() -> TerraformParser:
    """Create a TerraformParser instance."""
    return TerraformParser()


class TestTerraformResourceFieldPattern:
    """Tests for Terraform resource field pattern matching."""

    def test_detects_public_acl_in_s3_bucket(self, engine: RulesEngine, parser: TerraformParser, tmp_path: Path):
        """Test detection of public ACL in S3 bucket."""
        rule = Rule(
            id="TF001",
            name="tf-s3-public-acl",
            severity=Severity.CRITICAL,
            category="security",
            languages=["terraform"],
            description="S3 bucket with public ACL",
            message="S3 bucket should not have public ACL",
            pattern={
                "type": "resource",
                "resource_type": "aws_s3_bucket",
                "field": "acl",
                "contains": ["public-read", "public-read-write"],
            },
        )
        engine.register_rule(rule)

        tf_file = tmp_path / "main.tf"
        tf_file.write_text("""
resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}
""")

        parse_result = parser.parse_file(tf_file)
        findings = engine.check(parse_result, tf_file)

        assert len(findings) == 1
        assert findings[0].rule_id == "TF001"
        assert "aws_s3_bucket.public_bucket" in findings[0].code_snippet

    def test_no_match_for_private_acl(self, engine: RulesEngine, parser: TerraformParser, tmp_path: Path):
        """Test no finding for private ACL."""
        rule = Rule(
            id="TF001",
            name="tf-s3-public-acl",
            severity=Severity.CRITICAL,
            category="security",
            languages=["terraform"],
            description="S3 bucket with public ACL",
            message="S3 bucket should not have public ACL",
            pattern={
                "type": "resource",
                "resource_type": "aws_s3_bucket",
                "field": "acl",
                "contains": ["public-read", "public-read-write"],
            },
        )
        engine.register_rule(rule)

        tf_file = tmp_path / "main.tf"
        tf_file.write_text("""
resource "aws_s3_bucket" "private_bucket" {
  bucket = "my-private-bucket"
  acl    = "private"
}
""")

        parse_result = parser.parse_file(tf_file)
        findings = engine.check(parse_result, tf_file)

        assert len(findings) == 0


class TestTerraformResourceMissingBlockPattern:
    """Tests for Terraform resource missing block pattern matching."""

    def test_detects_missing_encryption_block(self, engine: RulesEngine, parser: TerraformParser, tmp_path: Path):
        """Test detection of missing encryption configuration."""
        rule = Rule(
            id="TF002",
            name="tf-s3-no-encryption",
            severity=Severity.HIGH,
            category="encryption",
            languages=["terraform"],
            description="S3 bucket without encryption",
            message="S3 bucket should have encryption enabled",
            pattern={
                "type": "resource",
                "resource_type": "aws_s3_bucket",
                "missing_block": "server_side_encryption_configuration",
            },
        )
        engine.register_rule(rule)

        tf_file = tmp_path / "main.tf"
        tf_file.write_text("""
resource "aws_s3_bucket" "unencrypted" {
  bucket = "my-bucket"
  acl    = "private"
}
""")

        parse_result = parser.parse_file(tf_file)
        findings = engine.check(parse_result, tf_file)

        assert len(findings) == 1
        assert findings[0].rule_id == "TF002"

    def test_no_match_when_encryption_block_present(self, engine: RulesEngine, parser: TerraformParser, tmp_path: Path):
        """Test no finding when encryption block is present."""
        rule = Rule(
            id="TF002",
            name="tf-s3-no-encryption",
            severity=Severity.HIGH,
            category="encryption",
            languages=["terraform"],
            description="S3 bucket without encryption",
            message="S3 bucket should have encryption enabled",
            pattern={
                "type": "resource",
                "resource_type": "aws_s3_bucket",
                "missing_block": "server_side_encryption_configuration",
            },
        )
        engine.register_rule(rule)

        tf_file = tmp_path / "main.tf"
        tf_file.write_text("""
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
""")

        parse_result = parser.parse_file(tf_file)
        findings = engine.check(parse_result, tf_file)

        assert len(findings) == 0


class TestTerraformResourceMissingFieldPattern:
    """Tests for Terraform resource missing field pattern matching."""

    def test_detects_missing_versioning(self, engine: RulesEngine, parser: TerraformParser, tmp_path: Path):
        """Test detection of missing versioning enabled."""
        rule = Rule(
            id="TF003",
            name="tf-s3-no-versioning",
            severity=Severity.MEDIUM,
            category="security",
            languages=["terraform"],
            description="S3 bucket without versioning",
            message="S3 bucket should have versioning enabled",
            pattern={
                "type": "resource",
                "resource_type": "aws_s3_bucket",
                "missing_field": "versioning_enabled",
                "expected_value": True,
            },
        )
        engine.register_rule(rule)

        tf_file = tmp_path / "main.tf"
        tf_file.write_text("""
resource "aws_s3_bucket" "no_versioning" {
  bucket = "my-bucket"
}
""")

        parse_result = parser.parse_file(tf_file)
        findings = engine.check(parse_result, tf_file)

        assert len(findings) == 1
        assert findings[0].rule_id == "TF003"

    def test_no_match_when_versioning_enabled(self, engine: RulesEngine, parser: TerraformParser, tmp_path: Path):
        """Test no finding when versioning is enabled."""
        rule = Rule(
            id="TF003",
            name="tf-s3-no-versioning",
            severity=Severity.MEDIUM,
            category="security",
            languages=["terraform"],
            description="S3 bucket without versioning",
            message="S3 bucket should have versioning enabled",
            pattern={
                "type": "resource",
                "resource_type": "aws_s3_bucket",
                "missing_field": "versioning_enabled",
                "expected_value": True,
            },
        )
        engine.register_rule(rule)

        tf_file = tmp_path / "main.tf"
        tf_file.write_text("""
resource "aws_s3_bucket" "versioned" {
  bucket = "my-bucket"
  versioning_enabled = true
}
""")

        parse_result = parser.parse_file(tf_file)
        findings = engine.check(parse_result, tf_file)

        assert len(findings) == 0


class TestTerraformVariablePattern:
    """Tests for Terraform variable pattern matching."""

    def test_detects_password_variable_with_default(self, engine: RulesEngine, parser: TerraformParser, tmp_path: Path):
        """Test detection of password variable with default value."""
        rule = Rule(
            id="TF004",
            name="tf-password-default",
            severity=Severity.CRITICAL,
            category="secrets",
            languages=["terraform"],
            description="Password variable with default",
            message="Password variables should not have default values",
            pattern={
                "type": "variable",
                "name_contains": ["password", "secret"],
                "has_default": True,
            },
        )
        engine.register_rule(rule)

        tf_file = tmp_path / "variables.tf"
        tf_file.write_text("""
variable "db_password" {
  description = "Database password"
  type        = string
  default     = "supersecret123"
}
""")

        parse_result = parser.parse_file(tf_file)
        findings = engine.check(parse_result, tf_file)

        assert len(findings) == 1
        assert findings[0].rule_id == "TF004"
        assert 'variable "db_password"' in findings[0].code_snippet

    def test_no_match_for_password_without_default(self, engine: RulesEngine, parser: TerraformParser, tmp_path: Path):
        """Test no finding for password variable without default."""
        rule = Rule(
            id="TF004",
            name="tf-password-default",
            severity=Severity.CRITICAL,
            category="secrets",
            languages=["terraform"],
            description="Password variable with default",
            message="Password variables should not have default values",
            pattern={
                "type": "variable",
                "name_contains": ["password", "secret"],
                "has_default": True,
            },
        )
        engine.register_rule(rule)

        tf_file = tmp_path / "variables.tf"
        tf_file.write_text("""
variable "db_password" {
  description = "Database password"
  type        = string
  sensitive   = true
}
""")

        parse_result = parser.parse_file(tf_file)
        findings = engine.check(parse_result, tf_file)

        assert len(findings) == 0


class TestTerraformLocalPattern:
    """Tests for Terraform local pattern matching."""

    def test_detects_secret_in_local(self, engine: RulesEngine, parser: TerraformParser, tmp_path: Path):
        """Test detection of secret values in locals."""
        rule = Rule(
            id="TF005",
            name="tf-secret-local",
            severity=Severity.HIGH,
            category="secrets",
            languages=["terraform"],
            description="Secret in local value",
            message="Secrets should not be stored in locals",
            pattern={
                "type": "local",
                "name_contains": ["password", "secret", "api_key"],
            },
        )
        engine.register_rule(rule)

        tf_file = tmp_path / "main.tf"
        tf_file.write_text("""
locals {
  db_password = "supersecret"
  api_key     = "sk-12345"
  app_name    = "myapp"
}
""")

        parse_result = parser.parse_file(tf_file)
        findings = engine.check(parse_result, tf_file)

        assert len(findings) == 2

    def test_no_match_for_clean_locals(self, engine: RulesEngine, parser: TerraformParser, tmp_path: Path):
        """Test no finding for locals without secrets."""
        rule = Rule(
            id="TF005",
            name="tf-secret-local",
            severity=Severity.HIGH,
            category="secrets",
            languages=["terraform"],
            description="Secret in local value",
            message="Secrets should not be stored in locals",
            pattern={
                "type": "local",
                "name_contains": ["password", "secret", "api_key"],
            },
        )
        engine.register_rule(rule)

        tf_file = tmp_path / "main.tf"
        tf_file.write_text("""
locals {
  app_name    = "myapp"
  environment = "production"
  region      = "us-east-1"
}
""")

        parse_result = parser.parse_file(tf_file)
        findings = engine.check(parse_result, tf_file)

        assert len(findings) == 0


class TestTerraformLanguageFilter:
    """Tests for language filtering."""

    def test_terraform_rule_does_not_match_python_file(self, engine: RulesEngine, tmp_path: Path):
        """Test Terraform rules don't match Python files."""
        from hackmenot.parsers.python import PythonParser

        py_parser = PythonParser()

        rule = Rule(
            id="TF001",
            name="tf-only-rule",
            severity=Severity.CRITICAL,
            category="test",
            languages=["terraform"],  # Terraform only
            description="Terraform only rule",
            message="Should not match Python files",
            pattern={
                "type": "resource",
                "resource_type": "aws_s3_bucket",
                "field": "acl",
                "contains": ["public"],
            },
        )
        engine.register_rule(rule)

        py_file = tmp_path / "test.py"
        py_file.write_text('bucket = {"acl": "public-read"}\n')

        parse_result = py_parser.parse_file(py_file)
        findings = engine.check(parse_result, py_file)

        assert len(findings) == 0

    def test_python_rule_does_not_match_terraform_file(self, engine: RulesEngine, parser: TerraformParser, tmp_path: Path):
        """Test Python rules don't match Terraform files."""
        rule = Rule(
            id="PY001",
            name="python-only-rule",
            severity=Severity.CRITICAL,
            category="test",
            languages=["python"],  # Python only
            description="Python only rule",
            message="Should not match Terraform files",
            pattern={
                "type": "fstring",
                "contains": ["password"],
            },
        )
        engine.register_rule(rule)

        tf_file = tmp_path / "main.tf"
        tf_file.write_text("""
variable "password" {
  type = string
}
""")

        parse_result = parser.parse_file(tf_file)
        findings = engine.check(parse_result, tf_file)

        assert len(findings) == 0


class TestTerraformTfvarsFile:
    """Tests for .tfvars file handling."""

    def test_detects_secret_in_tfvars(self, engine: RulesEngine, parser: TerraformParser, tmp_path: Path):
        """Test detection of secrets in .tfvars files."""
        rule = Rule(
            id="TF006",
            name="tf-tfvars-secret",
            severity=Severity.HIGH,
            category="secrets",
            languages=["terraform"],
            description="Secret in tfvars",
            message="Secrets in tfvars files may be committed to version control",
            pattern={
                "type": "local",  # tfvars are treated as locals
                "name_contains": ["password", "api_key"],
            },
        )
        engine.register_rule(rule)

        tfvars_file = tmp_path / "secrets.tfvars"
        tfvars_file.write_text("""
db_password = "supersecret123"
api_key     = "sk-12345"
region      = "us-east-1"
""")

        parse_result = parser.parse_file(tfvars_file)
        findings = engine.check(parse_result, tfvars_file)

        assert len(findings) == 2
