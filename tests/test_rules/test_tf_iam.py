"""Tests for Terraform IAM rules (TF_IAM001-TF_IAM003)."""

from pathlib import Path

import pytest

from hackmenot.core.scanner import Scanner


class TestTerraformIAMRules:
    """Tests for Terraform IAM rule detection."""

    @pytest.fixture
    def scanner(self):
        return Scanner()

    def test_wildcard_action_detected(self, scanner, tmp_path):
        """Test TF_IAM001 detects IAM policy with wildcard action."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_iam_policy" "wildcard_policy" {
  name        = "overly-permissive-policy"
  description = "Policy with wildcard action"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        "Action": "*"
        "Resource": "arn:aws:s3:::my-bucket/*"
      }
    ]
  })
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "TF_IAM001"]
        assert len(findings) == 1
        assert "wildcard_policy" in findings[0].code_snippet

    def test_wildcard_resource_detected(self, scanner, tmp_path):
        """Test TF_IAM002 detects IAM policy with wildcard resource."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_iam_policy" "wildcard_resource_policy" {
  name        = "overly-broad-policy"
  description = "Policy with wildcard resource"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        "Action": ["s3:GetObject", "s3:PutObject"]
        "Resource": "*"
      }
    ]
  })
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "TF_IAM002"]
        assert len(findings) == 1
        assert "wildcard_resource_policy" in findings[0].code_snippet

    def test_admin_policy_attachment_detected(self, scanner, tmp_path):
        """Test TF_IAM003 detects AdministratorAccess policy attachment."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_iam_role" "admin_role" {
  name = "admin-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "admin_attachment" {
  role       = aws_iam_role.admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "TF_IAM003"]
        assert len(findings) == 1
        assert "admin_attachment" in findings[0].code_snippet

    def test_secure_iam_no_findings(self, scanner, tmp_path):
        """Test that properly scoped IAM policies have no TF_IAM findings."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_iam_policy" "secure_policy" {
  name        = "secure-s3-policy"
  description = "Policy with specific actions and resources"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "arn:aws:s3:::my-bucket/*"
      }
    ]
  })
}

resource "aws_iam_role" "app_role" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "app_policy_attachment" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.secure_policy.arn
}
''')
        result = scanner.scan([tmp_path])
        iam_findings = [f for f in result.findings if f.rule_id.startswith("TF_IAM")]
        assert len(iam_findings) == 0
