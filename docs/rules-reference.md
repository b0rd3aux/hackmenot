# Rules Reference

hackmenot includes 100+ security rules across multiple categories.

## Categories

| Category | Description | Rule Count |
|----------|-------------|------------|
| Injection | SQL, command, code injection | 11 |
| Authentication | Missing auth, weak passwords | 8 |
| Cryptography | Weak algorithms, hardcoded keys | 10 |
| Data Exposure | Logging secrets, verbose errors | 7 |
| XSS | Cross-site scripting | 4 |
| Validation | Input validation issues | 8 |
| Dependencies | Hallucinated packages, CVEs | 3 |
| Go | Injection, crypto, auth, concurrency, unsafe | 23 |
| Terraform | S3, security groups, encryption, IAM, logging | 25 |

## Injection Rules

### INJ001 - SQL Injection (f-string)
- **Severity:** Critical
- **Languages:** Python
- **Description:** SQL query built using f-string with user input

```python
# Bad
query = f"SELECT * FROM users WHERE id = {user_id}"

# Good
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

### JSIJ001 - eval() Injection
- **Severity:** Critical
- **Languages:** JavaScript
- **Description:** Use of eval() with potentially untrusted input

```javascript
// Bad
eval(userInput);

// Good
JSON.parse(userInput);
```

## Dependency Rules

### DEP001 - Hallucinated Package
- **Severity:** High
- **Description:** Package not found in registry (may be AI-invented)

### DEP002 - Typosquat Package
- **Severity:** Critical
- **Description:** Package name similar to popular package

### DEP003 - Vulnerable Dependency
- **Severity:** Varies
- **Description:** Package has known CVE

## Go Rules

### GO_INJ001-GO_INJ006 - Injection
- **Severity:** Critical/High
- **Languages:** Go
- **Description:** SQL injection, command injection, template injection, and code injection vulnerabilities

| Rule ID | Description |
|---------|-------------|
| GO_INJ001 | SQL injection via string concatenation |
| GO_INJ002 | SQL injection via fmt.Sprintf |
| GO_INJ003 | Command injection via exec.Command |
| GO_INJ004 | Template injection in html/template |
| GO_INJ005 | LDAP injection |
| GO_INJ006 | XPath injection |

```go
// Bad
query := "SELECT * FROM users WHERE id = " + userId
db.Query(query)

// Good
db.Query("SELECT * FROM users WHERE id = ?", userId)
```

### GO_CRY001-GO_CRY005 - Cryptography
- **Severity:** High/Medium
- **Languages:** Go
- **Description:** Weak cryptographic algorithms and insecure key handling

| Rule ID | Description |
|---------|-------------|
| GO_CRY001 | Use of weak hash (MD5/SHA1) |
| GO_CRY002 | Hardcoded cryptographic key |
| GO_CRY003 | Weak random number generation |
| GO_CRY004 | Insecure TLS configuration |
| GO_CRY005 | Use of deprecated DES/RC4 |

```go
// Bad
h := md5.Sum(data)

// Good
h := sha256.Sum256(data)
```

### GO_AUT001-GO_AUT004 - Authentication
- **Severity:** High
- **Languages:** Go
- **Description:** Authentication and session management issues

| Rule ID | Description |
|---------|-------------|
| GO_AUT001 | Hardcoded credentials |
| GO_AUT002 | Missing authentication check |
| GO_AUT003 | Insecure session handling |
| GO_AUT004 | JWT none algorithm |

### GO_CON001-GO_CON003 - Concurrency
- **Severity:** Medium/High
- **Languages:** Go
- **Description:** Race conditions and unsafe concurrent access

| Rule ID | Description |
|---------|-------------|
| GO_CON001 | Data race on shared variable |
| GO_CON002 | Unsafe map concurrent access |
| GO_CON003 | Missing mutex protection |

```go
// Bad
var counter int
go func() { counter++ }()

// Good
var counter int64
go func() { atomic.AddInt64(&counter, 1) }()
```

### GO_UNS001-GO_UNS002, GO_NET001-GO_NET003 - Unsafe/Network
- **Severity:** High/Medium
- **Languages:** Go
- **Description:** Unsafe pointer usage and network security issues

| Rule ID | Description |
|---------|-------------|
| GO_UNS001 | Unsafe pointer conversion |
| GO_UNS002 | Unsafe.Sizeof misuse |
| GO_NET001 | Unvalidated redirect |
| GO_NET002 | Missing TLS verification |
| GO_NET003 | Binding to all interfaces |

## Terraform Rules

### TF_S3001-TF_S3004 - S3 Bucket Security
- **Severity:** High/Critical
- **Languages:** Terraform
- **Description:** S3 bucket misconfigurations

| Rule ID | Description |
|---------|-------------|
| TF_S3001 | S3 bucket public access enabled |
| TF_S3002 | S3 bucket encryption disabled |
| TF_S3003 | S3 bucket versioning disabled |
| TF_S3004 | S3 bucket logging disabled |

```hcl
# Bad
resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
}

# Good
resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
```

### TF_SG001-TF_SG004 - Security Groups
- **Severity:** Critical/High
- **Languages:** Terraform
- **Description:** Overly permissive security group rules

| Rule ID | Description |
|---------|-------------|
| TF_SG001 | Ingress from 0.0.0.0/0 |
| TF_SG002 | SSH open to the world |
| TF_SG003 | RDP open to the world |
| TF_SG004 | All ports open |

```hcl
# Bad
ingress {
  from_port   = 22
  to_port     = 22
  cidr_blocks = ["0.0.0.0/0"]
}

# Good
ingress {
  from_port   = 22
  to_port     = 22
  cidr_blocks = ["10.0.0.0/8"]
}
```

### TF_ENC001-TF_ENC004 - Encryption
- **Severity:** High
- **Languages:** Terraform
- **Description:** Missing encryption configurations

| Rule ID | Description |
|---------|-------------|
| TF_ENC001 | EBS volume not encrypted |
| TF_ENC002 | RDS instance not encrypted |
| TF_ENC003 | Elasticsearch not encrypted |
| TF_ENC004 | EFS not encrypted |

### TF_IAM001-TF_IAM003 - IAM
- **Severity:** Critical/High
- **Languages:** Terraform
- **Description:** Overly permissive IAM policies

| Rule ID | Description |
|---------|-------------|
| TF_IAM001 | IAM policy with * actions |
| TF_IAM002 | IAM policy with * resources |
| TF_IAM003 | IAM user with inline policy |

```hcl
# Bad
resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    Statement = [{
      Action   = "*"
      Resource = "*"
      Effect   = "Allow"
    }]
  })
}

# Good
resource "aws_iam_policy" "s3_read" {
  policy = jsonencode({
    Statement = [{
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::my-bucket/*"
      Effect   = "Allow"
    }]
  })
}
```

### TF_LOG001-TF_LOG003 - Logging
- **Severity:** Medium
- **Languages:** Terraform
- **Description:** Missing logging configurations

| Rule ID | Description |
|---------|-------------|
| TF_LOG001 | CloudTrail logging disabled |
| TF_LOG002 | VPC flow logs disabled |
| TF_LOG003 | ALB access logs disabled |

### TF_SEC001-TF_SEC004, TF_NET001-TF_NET002 - Secrets/Network
- **Severity:** Critical/High
- **Languages:** Terraform
- **Description:** Hardcoded secrets and network security issues

| Rule ID | Description |
|---------|-------------|
| TF_SEC001 | Hardcoded AWS access key |
| TF_SEC002 | Hardcoded password |
| TF_SEC003 | Hardcoded API key |
| TF_SEC004 | Sensitive data in output |
| TF_NET001 | Public IP on EC2 instance |
| TF_NET002 | Default VPC used |

## Listing All Rules

```bash
hackmenot rules
hackmenot rules INJ001
```
