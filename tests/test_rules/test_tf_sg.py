"""Tests for Terraform Security Group rules (TF_SG001-TF_SG004)."""

from pathlib import Path

import pytest

from hackmenot.core.scanner import Scanner


class TestTerraformSecurityGroupRules:
    """Tests for Terraform Security Group rule detection."""

    @pytest.fixture
    def scanner(self):
        return Scanner()

    def test_open_ingress_detected(self, scanner, tmp_path):
        """Test TF_SG001 detects security group with open ingress."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_security_group" "open_ingress" {
  name        = "open-ingress-sg"
  description = "Security group with open ingress"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "TF_SG001"]
        assert len(findings) == 1
        assert "open_ingress" in findings[0].code_snippet

    def test_open_egress_detected(self, scanner, tmp_path):
        """Test TF_SG002 detects security group with open egress."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_security_group" "open_egress" {
  name        = "open-egress-sg"
  description = "Security group with open egress"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "TF_SG002"]
        assert len(findings) == 1
        assert "open_egress" in findings[0].code_snippet

    def test_unrestricted_ssh_detected(self, scanner, tmp_path):
        """Test TF_SG003 detects security group rule with open SSH."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_security_group_rule" "ssh_open" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.main.id
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "TF_SG003"]
        assert len(findings) == 1
        assert "ssh_open" in findings[0].code_snippet

    def test_all_ports_open_detected(self, scanner, tmp_path):
        """Test TF_SG004 detects security group with all ports open."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_security_group" "all_ports" {
  name        = "all-ports-sg"
  description = "Security group with all ports open"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "TF_SG004"]
        assert len(findings) == 1
        assert "all_ports" in findings[0].code_snippet

    def test_secure_security_group_no_sg_findings(self, scanner, tmp_path):
        """Test that a properly restricted security group has no TF_SG findings."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_security_group" "secure_sg" {
  name        = "secure-sg"
  description = "Properly configured security group"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
''')
        result = scanner.scan([tmp_path])
        sg_findings = [f for f in result.findings if f.rule_id.startswith("TF_SG")]
        assert len(sg_findings) == 0
