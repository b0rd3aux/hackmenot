"""Tests for Terraform Secrets/Network rules (TF_SEC001-TF_SEC004, TF_NET001-TF_NET002)."""

from pathlib import Path

import pytest

from hackmenot.core.scanner import Scanner


class TestTerraformSecretsRules:
    """Tests for Terraform secrets and network rule detection."""

    @pytest.fixture
    def scanner(self):
        return Scanner()

    def test_hardcoded_secret_detected(self, scanner, tmp_path):
        """Test TF_SEC001 detects hardcoded secret in variable default."""
        tf_file = tmp_path / "variables.tf"
        tf_file.write_text('''
variable "api_key" {
  description = "API key for external service"
  type        = string
  default     = "sk-1234567890abcdef"
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "TF_SEC001"]
        assert len(findings) == 1
        assert "api_key" in findings[0].code_snippet

    def test_hardcoded_password_detected(self, scanner, tmp_path):
        """Test TF_SEC002 detects hardcoded password in variable default."""
        tf_file = tmp_path / "variables.tf"
        tf_file.write_text('''
variable "db_password" {
  description = "Database password"
  type        = string
  default     = "supersecretpassword123"
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "TF_SEC002"]
        assert len(findings) == 1
        assert "db_password" in findings[0].code_snippet

    def test_hardcoded_aws_key_detected(self, scanner, tmp_path):
        """Test TF_SEC003 detects hardcoded AWS access key."""
        tf_file = tmp_path / "variables.tf"
        tf_file.write_text('''
variable "aws_access_key_id" {
  description = "AWS access key"
  type        = string
  default     = "AKIAIOSFODNN7EXAMPLE"
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "TF_SEC003"]
        assert len(findings) == 1
        assert "aws_access" in findings[0].code_snippet

    def test_sensitive_not_set_detected(self, scanner, tmp_path):
        """Test TF_SEC004 detects sensitive variable without sensitive flag."""
        tf_file = tmp_path / "variables.tf"
        tf_file.write_text('''
variable "auth_token" {
  description = "Auth token for API"
  type        = string
  default     = "token123"
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "TF_SEC004"]
        assert len(findings) == 1
        assert "auth_token" in findings[0].code_snippet

    def test_public_subnet_detected(self, scanner, tmp_path):
        """Test TF_NET001 detects subnet with public IP assignment."""
        tf_file = tmp_path / "network.tf"
        tf_file.write_text('''
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "public-subnet"
  }
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "TF_NET001"]
        assert len(findings) == 1
        assert "public" in findings[0].code_snippet

    def test_missing_nacl_detected(self, scanner, tmp_path):
        """Test TF_NET002 detects subnet without explicit NACL."""
        tf_file = tmp_path / "network.tf"
        tf_file.write_text('''
resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "private-subnet"
  }
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "TF_NET002"]
        assert len(findings) == 1
        assert "private" in findings[0].code_snippet

    def test_secure_variable_no_findings(self, scanner, tmp_path):
        """Test that variable without default has no TF_SEC findings."""
        tf_file = tmp_path / "variables.tf"
        tf_file.write_text('''
variable "api_key" {
  description = "API key for external service"
  type        = string
  sensitive   = true
}

variable "db_password" {
  description = "Database password"
  type        = string
  sensitive   = true
}
''')
        result = scanner.scan([tmp_path])
        sec_findings = [f for f in result.findings if f.rule_id.startswith("TF_SEC")]
        assert len(sec_findings) == 0
