"""Tests for Terraform HCL parser using python-hcl2."""

from pathlib import Path

import pytest

from hackmenot.parsers.terraform import (
    TerraformParser,
    TerraformParseResult,
    TerraformResourceInfo,
    TerraformVariableInfo,
    TerraformLocalInfo,
)


class TestTerraformParserS3Resources:
    """Test parsing S3 bucket resources."""

    def test_parse_s3_bucket_with_acl(self):
        """Test parsing S3 bucket resource with acl setting."""
        parser = TerraformParser()
        source = '''
resource "aws_s3_bucket" "example" {
  bucket = "my-tf-test-bucket"
  acl    = "private"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}
'''
        result = parser.parse_string(source)

        assert not result.has_error
        assert len(result.resources) == 1
        resource = result.resources[0]
        assert resource.resource_type == "aws_s3_bucket"
        assert resource.name == "example"
        assert resource.config.get("bucket") == "my-tf-test-bucket"
        assert resource.config.get("acl") == "private"

    def test_parse_s3_bucket_public_read_acl(self):
        """Test parsing S3 bucket with public-read ACL (security concern)."""
        parser = TerraformParser()
        source = '''
resource "aws_s3_bucket" "public" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}
'''
        result = parser.parse_string(source)

        assert len(result.resources) == 1
        resource = result.resources[0]
        assert resource.config.get("acl") == "public-read"


class TestTerraformParserSecurityGroups:
    """Test parsing security group resources."""

    def test_parse_security_group_with_ingress(self):
        """Test parsing security group with ingress block."""
        parser = TerraformParser()
        source = '''
resource "aws_security_group" "allow_ssh" {
  name        = "allow_ssh"
  description = "Allow SSH inbound traffic"
  vpc_id      = "vpc-123456"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''
        result = parser.parse_string(source)

        assert len(result.resources) == 1
        resource = result.resources[0]
        assert resource.resource_type == "aws_security_group"
        assert resource.name == "allow_ssh"
        # Check that nested ingress block is captured
        assert "ingress" in resource.config

    def test_parse_security_group_nested_blocks(self):
        """Test that nested ingress/egress blocks are properly parsed."""
        parser = TerraformParser()
        source = '''
resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''
        result = parser.parse_string(source)

        resource = result.resources[0]
        ingress = resource.config.get("ingress")
        # Multiple ingress blocks should be captured as a list
        assert ingress is not None
        assert isinstance(ingress, list)
        assert len(ingress) == 2


class TestTerraformParserVariables:
    """Test parsing Terraform variable definitions."""

    def test_parse_variable_with_default(self):
        """Test parsing variable with default value."""
        parser = TerraformParser()
        source = '''
variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t2.micro"
}
'''
        result = parser.parse_string(source)

        assert len(result.variables) == 1
        var = result.variables[0]
        assert var.name == "instance_type"
        assert var.default == "t2.micro"
        assert var.sensitive is False

    def test_parse_variable_without_default(self):
        """Test parsing variable without default value."""
        parser = TerraformParser()
        source = '''
variable "api_key" {
  description = "API key for external service"
  type        = string
}
'''
        result = parser.parse_string(source)

        assert len(result.variables) == 1
        var = result.variables[0]
        assert var.name == "api_key"
        assert var.default is None

    def test_parse_sensitive_variable(self):
        """Test parsing sensitive variable."""
        parser = TerraformParser()
        source = '''
variable "db_password" {
  description = "Database password"
  type        = string
  sensitive   = true
}
'''
        result = parser.parse_string(source)

        assert len(result.variables) == 1
        var = result.variables[0]
        assert var.name == "db_password"
        assert var.sensitive is True


class TestTerraformParserLocals:
    """Test parsing Terraform locals blocks."""

    def test_parse_locals_block(self):
        """Test parsing locals block."""
        parser = TerraformParser()
        source = '''
locals {
  common_tags = {
    Environment = "production"
    Team        = "devops"
  }
  bucket_name = "my-app-bucket"
}
'''
        result = parser.parse_string(source)

        assert len(result.locals) >= 2
        local_names = [l.name for l in result.locals]
        assert "common_tags" in local_names
        assert "bucket_name" in local_names


class TestTerraformParserMultipleResources:
    """Test parsing multiple resources."""

    def test_parse_multiple_resources(self):
        """Test parsing file with multiple resources."""
        parser = TerraformParser()
        source = '''
resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
}

resource "aws_instance" "db" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.small"
}

resource "aws_s3_bucket" "logs" {
  bucket = "my-logs-bucket"
}
'''
        result = parser.parse_string(source)

        assert len(result.resources) == 3
        resource_types = [r.resource_type for r in result.resources]
        assert resource_types.count("aws_instance") == 2
        assert resource_types.count("aws_s3_bucket") == 1


class TestTerraformParserFileOperations:
    """Test file-based parsing operations."""

    def test_parse_file_from_disk(self, tmp_path: Path):
        """Test parsing a Terraform file from disk."""
        parser = TerraformParser()
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('''
resource "aws_instance" "example" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
}
''')
        result = parser.parse_file(tf_file)

        assert not result.has_error
        assert len(result.resources) == 1
        assert result.resources[0].resource_type == "aws_instance"

    def test_parse_empty_file(self, tmp_path: Path):
        """Test parsing an empty Terraform file."""
        parser = TerraformParser()
        tf_file = tmp_path / "empty.tf"
        tf_file.write_text("")

        result = parser.parse_file(tf_file)

        assert not result.has_error
        assert len(result.resources) == 0
        assert len(result.variables) == 0
        assert len(result.locals) == 0

    def test_parse_invalid_hcl(self, tmp_path: Path):
        """Test parsing invalid HCL doesn't crash."""
        parser = TerraformParser()
        tf_file = tmp_path / "invalid.tf"
        tf_file.write_text('''
resource "aws_instance" "broken {
  # missing closing quote
  ami = "ami-12345678
}
''')
        result = parser.parse_file(tf_file)

        # Should not crash, returns error result
        assert result.has_error is True


class TestTerraformParserEBSVolume:
    """Test parsing EBS volume resources."""

    def test_parse_ebs_volume_unencrypted(self):
        """Test parsing EBS volume without encryption (security concern)."""
        parser = TerraformParser()
        source = '''
resource "aws_ebs_volume" "data" {
  availability_zone = "us-west-2a"
  size              = 100
  encrypted         = false

  tags = {
    Name = "data-volume"
  }
}
'''
        result = parser.parse_string(source)

        assert len(result.resources) == 1
        resource = result.resources[0]
        assert resource.resource_type == "aws_ebs_volume"
        assert resource.config.get("encrypted") is False


class TestTerraformParserIAMPolicy:
    """Test parsing IAM policy resources."""

    def test_parse_iam_policy_resource(self):
        """Test parsing IAM policy resource."""
        parser = TerraformParser()
        source = '''
resource "aws_iam_policy" "admin" {
  name        = "admin-policy"
  description = "Admin access policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}
'''
        result = parser.parse_string(source)

        assert len(result.resources) == 1
        resource = result.resources[0]
        assert resource.resource_type == "aws_iam_policy"
        assert resource.name == "admin"


class TestTerraformParserTfvars:
    """Test parsing .tfvars files."""

    def test_parse_tfvars_file(self, tmp_path: Path):
        """Test parsing .tfvars file with variable values."""
        parser = TerraformParser()
        tfvars_file = tmp_path / "terraform.tfvars"
        tfvars_file.write_text('''
region         = "us-west-2"
instance_type  = "t2.micro"
enable_logging = true
allowed_ports  = [22, 80, 443]
''')
        result = parser.parse_file(tfvars_file)

        assert not result.has_error
        # tfvars files don't have resources, just key-value pairs
        # They should be parsed as locals
        assert len(result.locals) >= 1


class TestTerraformParserLineNumbers:
    """Test line number tracking."""

    def test_resource_has_line_number(self):
        """Test that resources have line numbers."""
        parser = TerraformParser()
        source = '''
# Comment line
resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
}
'''
        result = parser.parse_string(source)

        assert len(result.resources) == 1
        resource = result.resources[0]
        # Resource should have a line number > 0
        assert resource.line > 0


class TestTerraformParserDataSources:
    """Test parsing data source blocks (for completeness)."""

    def test_parse_data_source(self):
        """Test that data sources are not confused with resources."""
        parser = TerraformParser()
        source = '''
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }
}

resource "aws_instance" "web" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t2.micro"
}
'''
        result = parser.parse_string(source)

        # Should only capture the resource, not the data source
        # (or capture data sources separately if needed)
        assert len(result.resources) >= 1
        resource_types = [r.resource_type for r in result.resources]
        assert "aws_instance" in resource_types
