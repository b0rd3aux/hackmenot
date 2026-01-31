"""Tests for Terraform logging rules (TF_LOG001-TF_LOG003)."""

from pathlib import Path

import pytest

from hackmenot.core.scanner import Scanner


class TestTerraformLoggingRules:
    """Tests for Terraform logging rule detection."""

    @pytest.fixture
    def scanner(self):
        return Scanner()

    def test_cloudtrail_disabled_detected(self, scanner, tmp_path):
        """Test TF_LOG001 detects CloudTrail without enable_logging."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_cloudtrail" "insecure_trail" {
  name                          = "my-trail"
  s3_bucket_name                = aws_s3_bucket.trail_bucket.id
  include_global_service_events = true
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "TF_LOG001"]
        assert len(findings) == 1
        assert "insecure_trail" in findings[0].code_snippet

    def test_vpc_missing_flow_logs_detected(self, scanner, tmp_path):
        """Test TF_LOG002 detects VPC without flow logs."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "main-vpc"
  }
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "TF_LOG002"]
        assert len(findings) == 1
        assert "main" in findings[0].code_snippet

    def test_alb_missing_access_logs_detected(self, scanner, tmp_path):
        """Test TF_LOG003 detects ALB without access logs."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_lb" "app" {
  name               = "app-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = [aws_subnet.public_a.id, aws_subnet.public_b.id]
  security_groups    = [aws_security_group.alb.id]
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "TF_LOG003"]
        assert len(findings) == 1
        assert "app" in findings[0].code_snippet

    def test_secure_logging_no_findings(self, scanner, tmp_path):
        """Test that properly configured logging resources have no TF_LOG findings."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_cloudtrail" "secure_trail" {
  name                          = "secure-trail"
  s3_bucket_name                = aws_s3_bucket.trail_bucket.id
  include_global_service_events = true
  enable_logging                = true
}

resource "aws_lb" "app" {
  name               = "app-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = [aws_subnet.public_a.id, aws_subnet.public_b.id]

  access_logs {
    bucket  = aws_s3_bucket.logs.id
    prefix  = "alb-logs"
    enabled = true
  }
}
''')
        result = scanner.scan([tmp_path])
        log_findings = [f for f in result.findings if f.rule_id.startswith("TF_LOG")]
        assert len(log_findings) == 0
