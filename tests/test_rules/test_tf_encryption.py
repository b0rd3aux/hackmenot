"""Tests for Terraform Encryption rules (TF_ENC001-TF_ENC004)."""

from pathlib import Path

import pytest

from hackmenot.core.scanner import Scanner


class TestTerraformEncryptionRules:
    """Tests for Terraform Encryption rule detection."""

    @pytest.fixture
    def scanner(self):
        return Scanner()

    def test_ebs_no_encryption_detected(self, scanner, tmp_path):
        """Test TF_ENC001 detects EBS volume without encryption."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-east-1a"
  size              = 100
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "TF_ENC001"]
        assert len(findings) == 1
        assert "unencrypted" in findings[0].code_snippet

    def test_rds_no_encryption_detected(self, scanner, tmp_path):
        """Test TF_ENC002 detects RDS instance without storage encryption."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_db_instance" "unencrypted_db" {
  identifier           = "mydb"
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "password123"
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "TF_ENC002"]
        assert len(findings) == 1
        assert "unencrypted_db" in findings[0].code_snippet

    def test_elasticache_no_encryption_detected(self, scanner, tmp_path):
        """Test TF_ENC003 detects ElastiCache without encryption at rest."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_elasticache_replication_group" "unencrypted_cache" {
  replication_group_id          = "my-cache"
  replication_group_description = "My cache cluster"
  node_type                     = "cache.t3.micro"
  number_cache_clusters         = 2
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "TF_ENC003"]
        assert len(findings) == 1
        assert "unencrypted_cache" in findings[0].code_snippet

    def test_sqs_no_encryption_detected(self, scanner, tmp_path):
        """Test TF_ENC004 detects SQS queue without encryption."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_sqs_queue" "unencrypted_queue" {
  name = "my-queue"
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "TF_ENC004"]
        assert len(findings) == 1
        assert "unencrypted_queue" in findings[0].code_snippet

    def test_encrypted_resources_no_enc_findings(self, scanner, tmp_path):
        """Test that properly encrypted resources have no TF_ENC findings."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_ebs_volume" "encrypted_volume" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true
}

resource "aws_db_instance" "encrypted_db" {
  identifier           = "mydb"
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "password123"
  storage_encrypted    = true
}

resource "aws_elasticache_replication_group" "encrypted_cache" {
  replication_group_id          = "my-cache"
  replication_group_description = "My cache cluster"
  node_type                     = "cache.t3.micro"
  number_cache_clusters         = 2
  at_rest_encryption_enabled    = true
}

resource "aws_sqs_queue" "encrypted_queue" {
  name              = "my-queue"
  kms_master_key_id = "alias/aws/sqs"
}
''')
        result = scanner.scan([tmp_path])
        enc_findings = [f for f in result.findings if f.rule_id.startswith("TF_ENC")]
        assert len(enc_findings) == 0
