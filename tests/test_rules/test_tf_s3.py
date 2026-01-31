"""Tests for Terraform S3 rules (TF_S3001-TF_S3004)."""

from pathlib import Path

import pytest

from hackmenot.core.scanner import Scanner


class TestTerraformS3Rules:
    """Tests for Terraform S3 rule detection."""

    @pytest.fixture
    def scanner(self):
        return Scanner()

    def test_public_bucket_detected(self, scanner, tmp_path):
        """Test TF_S3001 detects public S3 bucket ACL."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "TF_S3001"]
        assert len(findings) == 1
        assert "public_bucket" in findings[0].code_snippet

    def test_no_encryption_detected(self, scanner, tmp_path):
        """Test TF_S3002 detects S3 bucket without encryption."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_s3_bucket" "unencrypted" {
  bucket = "my-bucket"
  acl    = "private"
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "TF_S3002"]
        assert len(findings) == 1

    def test_no_versioning_detected(self, scanner, tmp_path):
        """Test TF_S3003 detects S3 bucket without versioning."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_s3_bucket" "no_versioning" {
  bucket = "my-bucket"
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "TF_S3003"]
        assert len(findings) == 1

    def test_no_logging_detected(self, scanner, tmp_path):
        """Test TF_S3004 detects S3 bucket without logging."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_s3_bucket" "no_logging" {
  bucket = "my-bucket"
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "TF_S3004"]
        assert len(findings) == 1

    def test_secure_bucket_no_s3_findings(self, scanner, tmp_path):
        """Test that a fully secured S3 bucket has no TF_S3 findings."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-bucket"
  acl    = "private"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  logging {
    target_bucket = "my-logs-bucket"
    target_prefix = "logs/"
  }
}
''')
        result = scanner.scan([tmp_path])
        s3_findings = [f for f in result.findings if f.rule_id.startswith("TF_S3")]
        assert len(s3_findings) == 0
