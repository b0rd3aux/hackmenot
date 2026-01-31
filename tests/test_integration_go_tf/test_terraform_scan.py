"""Integration tests for Terraform scanning."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from hackmenot.cli.main import app
from hackmenot.core.scanner import Scanner

runner = CliRunner()


class TestTerraformIntegration:
    """End-to-end tests for scanning Terraform files."""

    def test_full_scan_terraform_project(self, tmp_path: Path):
        """Test full scan of Terraform project with multiple issues."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_s3_bucket" "public" {
  bucket = "my-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "open" {
  name = "open"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

variable "db_password" {
  default = "supersecret123"
}
''')
        scanner = Scanner()
        result = scanner.scan([tmp_path])

        assert result.files_scanned == 1
        rule_ids = {f.rule_id for f in result.findings}
        # Should detect multiple issues
        assert "TF_S3001" in rule_ids  # Public bucket
        assert "TF_SG001" in rule_ids  # Open ingress
        assert "TF_SEC002" in rule_ids  # Hardcoded password

    def test_terraform_cli_scan(self, tmp_path: Path):
        """Test CLI scan of Terraform files."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_s3_bucket" "test" {
  bucket = "test"
  acl    = "public-read-write"
}
''')
        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert "TF_S3001" in result.stdout or "public" in result.stdout.lower()

    def test_terraform_json_output(self, tmp_path: Path):
        """Test JSON output for Terraform scan."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size = 100
}
''')
        result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
        import json
        data = json.loads(result.stdout)
        assert "findings" in data

    def test_tfvars_scanning(self, tmp_path: Path):
        """Test scanning of .tfvars files."""
        tfvars = tmp_path / "secrets.tfvars"
        tfvars.write_text('''
db_password = "supersecret"
api_key = "sk-12345"
''')
        scanner = Scanner()
        result = scanner.scan([tmp_path])
        assert result.files_scanned == 1

    def test_clean_terraform_no_findings(self, tmp_path: Path):
        """Test that secure Terraform has no findings."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_s3_bucket" "secure" {
  bucket = "my-secure-bucket"
  acl    = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  versioning {
    enabled = true
  }

  logging {
    target_bucket = "log-bucket"
  }
}
''')
        scanner = Scanner()
        result = scanner.scan([tmp_path])
        s3_findings = [f for f in result.findings if f.rule_id.startswith("TF_S3")]
        assert len(s3_findings) == 0
