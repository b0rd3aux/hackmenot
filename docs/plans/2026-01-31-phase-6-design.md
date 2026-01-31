# Phase 6: Go and Terraform Support - Design Document

## Overview

Add comprehensive security scanning for Go and Terraform (HCL) files, expanding hackmenot's language coverage from 2 languages to 4.

**Goals:**
- Go language support with 23 security rules
- Terraform HCL support with 24 security rules
- Maintain existing architecture patterns
- ~119 new tests

## Go Language Support

### Parser Architecture

New `GoParser` class using `tree-sitter-go` for AST parsing with manual tree-walking (matching existing JavaScript pattern).

**Info classes:**

```python
@dataclass
class GoCallInfo:
    name: str           # "fmt.Sprintf", "db.Query", "exec.Command"
    args: list[str]     # Argument values/expressions
    line: int
    column: int

@dataclass
class GoAssignmentInfo:
    target: str         # Variable name
    value: str          # Assigned value/expression
    line: int
    column: int

@dataclass
class GoStringInfo:
    value: str          # String literal content
    is_formatted: bool  # Uses fmt.Sprintf or string concat with variables
    line: int
    column: int
```

**Tree-sitter node types:**
- `call_expression` → GoCallInfo
- `short_var_declaration`, `assignment_statement` → GoAssignmentInfo
- `interpreted_string_literal`, `raw_string_literal` → GoStringInfo
- `function_declaration` → GoFunctionInfo

**File extensions:** `.go`

### Go Rules (23 total)

#### Injection (6 rules)
| ID | Name | Severity | Pattern |
|----|------|----------|---------|
| GO_INJ001 | sql-injection | CRITICAL | `db.Query/Exec` with string concat/Sprintf |
| GO_INJ002 | command-injection | CRITICAL | `exec.Command` with variables |
| GO_INJ003 | path-traversal | HIGH | `filepath.Join` with user input patterns |
| GO_INJ004 | ldap-injection | HIGH | LDAP queries with string formatting |
| GO_INJ005 | xpath-injection | HIGH | XPath with string formatting |
| GO_INJ006 | template-injection | HIGH | `template.HTML` with variables |

#### Cryptography (5 rules)
| ID | Name | Severity | Pattern |
|----|------|----------|---------|
| GO_CRY001 | weak-hash-md5 | MEDIUM | `md5.New()`, `md5.Sum()` |
| GO_CRY002 | weak-hash-sha1 | MEDIUM | `sha1.New()`, `sha1.Sum()` |
| GO_CRY003 | insecure-tls | HIGH | `InsecureSkipVerify: true` |
| GO_CRY004 | weak-random | MEDIUM | `math/rand` for security |
| GO_CRY005 | hardcoded-iv | HIGH | Static IV in crypto |

#### Auth/Secrets (4 rules)
| ID | Name | Severity | Pattern |
|----|------|----------|---------|
| GO_AUT001 | hardcoded-password | HIGH | `password =` string literals |
| GO_AUT002 | hardcoded-secret | HIGH | `secret`, `apiKey` literals |
| GO_AUT003 | hardcoded-token | HIGH | `token =` string literals |
| GO_AUT004 | empty-password | CRITICAL | Empty string passwords |

#### Concurrency (3 rules)
| ID | Name | Severity | Pattern |
|----|------|----------|---------|
| GO_CON001 | data-race | MEDIUM | Shared variable without mutex |
| GO_CON002 | goroutine-leak | MEDIUM | Unbounded goroutine creation |
| GO_CON003 | channel-deadlock | MEDIUM | Unbuffered channel patterns |

#### Unsafe/Network (5 rules)
| ID | Name | Severity | Pattern |
|----|------|----------|---------|
| GO_UNS001 | unsafe-pointer | HIGH | `unsafe.Pointer` usage |
| GO_UNS002 | cgo-usage | MEDIUM | CGO import detection |
| GO_NET001 | ssrf | HIGH | HTTP client with variable URLs |
| GO_NET002 | open-redirect | MEDIUM | Redirect with user input |
| GO_NET003 | unvalidated-url | MEDIUM | URL parsing without validation |

## Terraform Support

### Parser Architecture

New `TerraformParser` class using `python-hcl2` library (pure Python HCL2 parser).

**Info classes:**

```python
@dataclass
class TerraformResourceInfo:
    resource_type: str    # "aws_s3_bucket", "aws_security_group"
    name: str             # Resource name
    config: dict          # Full resource configuration
    line: int

@dataclass
class TerraformVariableInfo:
    name: str             # Variable name
    default: Any          # Default value (if set)
    line: int

@dataclass
class TerraformLocalInfo:
    name: str             # Local name
    value: Any            # Value expression
    line: int
```

**New pattern type for rules:**

```yaml
# Check for missing blocks
pattern:
  type: resource
  resource_type: aws_s3_bucket
  missing_block: server_side_encryption_configuration

# Check for dangerous values
pattern:
  type: resource
  resource_type: aws_security_group_rule
  field: cidr_blocks
  contains: "0.0.0.0/0"
```

**File extensions:** `.tf`, `.tfvars`

### Terraform Rules (24 total)

#### S3 (4 rules)
| ID | Name | Severity | Pattern |
|----|------|----------|---------|
| TF_S3001 | s3-public-bucket | CRITICAL | `acl = "public-read"` or `"public-read-write"` |
| TF_S3002 | s3-no-encryption | HIGH | Missing `server_side_encryption_configuration` |
| TF_S3003 | s3-no-versioning | MEDIUM | Missing `versioning { enabled = true }` |
| TF_S3004 | s3-no-logging | LOW | Missing `logging` block |

#### Security Groups (4 rules)
| ID | Name | Severity | Pattern |
|----|------|----------|---------|
| TF_SG001 | sg-open-ingress | CRITICAL | `cidr_blocks = ["0.0.0.0/0"]` on ingress |
| TF_SG002 | sg-open-egress | MEDIUM | `cidr_blocks = ["0.0.0.0/0"]` on egress |
| TF_SG003 | sg-unrestricted-port | HIGH | Open SSH (22), RDP (3389) to 0.0.0.0/0 |
| TF_SG004 | sg-all-ports | CRITICAL | `from_port = 0, to_port = 65535` |

#### Encryption (4 rules)
| ID | Name | Severity | Pattern |
|----|------|----------|---------|
| TF_ENC001 | ebs-no-encryption | HIGH | `aws_ebs_volume` without `encrypted = true` |
| TF_ENC002 | rds-no-encryption | HIGH | `aws_db_instance` without `storage_encrypted` |
| TF_ENC003 | elasticache-no-encryption | HIGH | Missing `at_rest_encryption_enabled` |
| TF_ENC004 | sqs-no-encryption | MEDIUM | Missing `kms_master_key_id` |

#### IAM (3 rules)
| ID | Name | Severity | Pattern |
|----|------|----------|---------|
| TF_IAM001 | iam-wildcard-action | HIGH | `Action = ["*"]` in policy |
| TF_IAM002 | iam-wildcard-resource | HIGH | `Resource = ["*"]` in policy |
| TF_IAM003 | iam-admin-policy | CRITICAL | `AdministratorAccess` attachment |

#### Logging (3 rules)
| ID | Name | Severity | Pattern |
|----|------|----------|---------|
| TF_LOG001 | cloudtrail-disabled | HIGH | Missing `aws_cloudtrail` resource |
| TF_LOG002 | flow-logs-disabled | MEDIUM | VPC without `aws_flow_log` |
| TF_LOG003 | alb-no-access-logs | LOW | ALB without `access_logs` |

#### Secrets/Network (6 rules)
| ID | Name | Severity | Pattern |
|----|------|----------|---------|
| TF_SEC001 | hardcoded-secret | CRITICAL | `default = "..."` with secret patterns |
| TF_SEC002 | hardcoded-password | CRITICAL | Password in variable default |
| TF_SEC003 | hardcoded-aws-key | CRITICAL | AWS access key patterns |
| TF_SEC004 | sensitive-not-set | MEDIUM | Secret variable without `sensitive = true` |
| TF_NET001 | public-subnet | MEDIUM | `map_public_ip_on_launch = true` |
| TF_NET002 | missing-nacl | LOW | Subnet without explicit NACL |

## Scanner Integration

**Scanner updates:**

```python
SUPPORTED_EXTENSIONS = {".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".go", ".tf", ".tfvars"}

GO_EXTENSIONS = {".go"}
TERRAFORM_EXTENSIONS = {".tf", ".tfvars"}

def __init__(self, ...):
    self.parser = PythonParser()
    self.js_parser = JavaScriptParser()
    self.go_parser = GoParser()
    self.tf_parser = TerraformParser()

def _detect_language(self, file_path: Path) -> str:
    if file_path.suffix in self.GO_EXTENSIONS:
        return "go"
    if file_path.suffix in self.TERRAFORM_EXTENSIONS:
        return "terraform"
    # ... existing logic
```

**Engine updates:**

```python
# Extension map additions
".go": "go",
".tf": "terraform",
".tfvars": "terraform",

# New pattern matching methods
def _check_go_rule(self, rule, parse_result, file_path) -> list[Finding]
def _check_terraform_rule(self, rule, parse_result, file_path) -> list[Finding]
```

## Dependencies

```toml
# pyproject.toml additions
dependencies = [
    "tree-sitter-go>=0.21.0",
    "python-hcl2>=4.3.0",
]
```

## Rule File Organization

```
builtin/
├── go/
│   ├── GO_INJ001.yml
│   ├── GO_INJ002.yml
│   ├── GO_CRY001.yml
│   └── ...
└── terraform/
    ├── TF_S3001.yml
    ├── TF_SG001.yml
    ├── TF_ENC001.yml
    └── ...
```

## Testing Strategy

**Test structure:**

```
tests/
├── test_parsers/
│   ├── test_golang.py           # ~15 tests
│   └── test_terraform.py        # ~15 tests
├── test_rules/
│   ├── test_go_rules.py         # ~25 tests
│   └── test_terraform_rules.py  # ~25 tests
└── test_integration/
    ├── test_go_scan.py          # ~5 tests
    └── test_terraform_scan.py   # ~5 tests
```

**Test fixtures:**

```
tests/fixtures/
├── go/
│   ├── vulnerable.go
│   └── clean.go
└── terraform/
    ├── vulnerable.tf
    └── clean.tf
```

## Implementation Tasks

| # | Task | Dependencies |
|---|------|--------------|
| 1 | Add tree-sitter-go and python-hcl2 to pyproject.toml | None |
| 2 | Create GoParser with info classes | Task 1 |
| 3 | Create TerraformParser with info classes | Task 1 |
| 4 | Integrate GoParser into Scanner | Task 2 |
| 5 | Integrate TerraformParser into Scanner | Task 3 |
| 6 | Add Go pattern matching to RulesEngine | Task 4 |
| 7 | Add Terraform pattern matching to RulesEngine | Task 5 |
| 8 | Implement Go injection rules (6 rules) | Task 6 |
| 9 | Implement Go crypto rules (5 rules) | Task 6 |
| 10 | Implement Go auth/secrets rules (4 rules) | Task 6 |
| 11 | Implement Go concurrency rules (3 rules) | Task 6 |
| 12 | Implement Go unsafe/network rules (5 rules) | Task 6 |
| 13 | Implement Terraform S3 rules (4 rules) | Task 7 |
| 14 | Implement Terraform security group rules (4 rules) | Task 7 |
| 15 | Implement Terraform encryption rules (4 rules) | Task 7 |
| 16 | Implement Terraform IAM rules (3 rules) | Task 7 |
| 17 | Implement Terraform logging rules (3 rules) | Task 7 |
| 18 | Implement Terraform secrets/network rules (6 rules) | Task 7 |
| 19 | Integration tests for Go scanning | Tasks 8-12 |
| 20 | Integration tests for Terraform scanning | Tasks 13-18 |
| 21 | Update CLI help and docs | Tasks 19-20 |

**Total: 21 tasks, 47 rules, ~119 new tests**
