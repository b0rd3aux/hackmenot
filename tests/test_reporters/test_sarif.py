"""Tests for SARIF reporter."""

import json

from hackmenot.core.models import Finding, ScanResult, Severity
from hackmenot.reporters.sarif import SARIFReporter


def test_sarif_output_valid_json():
    """Test output is valid JSON with $schema and runs."""
    reporter = SARIFReporter()
    findings = [
        Finding(
            rule_id="INJ001",
            rule_name="sql-injection",
            severity=Severity.CRITICAL,
            message="SQL injection detected",
            file_path="src/api.py",
            line_number=42,
            column=5,
            code_snippet='f"SELECT * FROM users WHERE id = {user_id}"',
            fix_suggestion="Use parameterized queries",
            education="AI often generates vulnerable SQL",
        ),
    ]
    result = ScanResult(files_scanned=10, findings=findings, scan_time_ms=150)

    output = reporter.render(result)

    # Should be valid JSON
    sarif = json.loads(output)

    # Should have required SARIF structure
    assert "$schema" in sarif
    assert "sarif-schema-2.1.0" in sarif["$schema"]
    assert sarif["version"] == "2.1.0"
    assert "runs" in sarif
    assert len(sarif["runs"]) == 1


def test_sarif_contains_results():
    """Test results have ruleId, level, locations."""
    reporter = SARIFReporter()
    findings = [
        Finding(
            rule_id="INJ001",
            rule_name="sql-injection",
            severity=Severity.CRITICAL,
            message="SQL injection detected",
            file_path="src/api.py",
            line_number=42,
            column=5,
            code_snippet='f"SELECT * FROM users WHERE id = {user_id}"',
            fix_suggestion="Use parameterized queries",
            education="AI often generates vulnerable SQL",
        ),
        Finding(
            rule_id="AUTH001",
            rule_name="missing-auth",
            severity=Severity.HIGH,
            message="Missing authentication",
            file_path="src/api.py",
            line_number=50,
            column=0,
            code_snippet="def get_users():",
            fix_suggestion="Add @login_required",
            education="AI skips auth decorators",
        ),
    ]
    result = ScanResult(files_scanned=10, findings=findings, scan_time_ms=150)

    output = reporter.render(result)
    sarif = json.loads(output)

    results = sarif["runs"][0]["results"]
    assert len(results) == 2

    # Check first result
    r = results[0]
    assert r["ruleId"] == "INJ001"
    assert r["level"] == "error"  # CRITICAL maps to error
    assert "message" in r
    assert r["message"]["text"] == "SQL injection detected"
    assert "locations" in r
    assert len(r["locations"]) == 1

    loc = r["locations"][0]
    assert "physicalLocation" in loc
    phys = loc["physicalLocation"]
    assert phys["artifactLocation"]["uri"] == "src/api.py"
    assert phys["region"]["startLine"] == 42
    assert phys["region"]["startColumn"] == 5

    # Check second result
    r2 = results[1]
    assert r2["ruleId"] == "AUTH001"
    assert r2["level"] == "error"  # HIGH maps to error


def test_sarif_contains_rules():
    """Test tool.driver.rules has rule definitions."""
    reporter = SARIFReporter()
    findings = [
        Finding(
            rule_id="INJ001",
            rule_name="sql-injection",
            severity=Severity.CRITICAL,
            message="SQL injection detected",
            file_path="src/api.py",
            line_number=42,
            column=5,
            code_snippet='f"SELECT * FROM users WHERE id = {user_id}"',
            fix_suggestion="Use parameterized queries",
            education="AI often generates vulnerable SQL",
        ),
        Finding(
            rule_id="AUTH001",
            rule_name="missing-auth",
            severity=Severity.MEDIUM,
            message="Missing authentication",
            file_path="src/api.py",
            line_number=50,
            column=0,
            code_snippet="def get_users():",
            fix_suggestion="Add @login_required",
            education="AI skips auth decorators",
        ),
    ]
    result = ScanResult(files_scanned=10, findings=findings, scan_time_ms=150)

    output = reporter.render(result)
    sarif = json.loads(output)

    tool = sarif["runs"][0]["tool"]
    assert "driver" in tool
    driver = tool["driver"]
    assert driver["name"] == "hackmenot"
    assert "version" in driver
    assert "rules" in driver

    rules = driver["rules"]
    assert len(rules) == 2

    # Find INJ001 rule
    inj_rule = next((r for r in rules if r["id"] == "INJ001"), None)
    assert inj_rule is not None
    assert inj_rule["name"] == "sql-injection"
    assert "shortDescription" in inj_rule
    assert "defaultConfiguration" in inj_rule
    assert inj_rule["defaultConfiguration"]["level"] == "error"

    # Find AUTH001 rule
    auth_rule = next((r for r in rules if r["id"] == "AUTH001"), None)
    assert auth_rule is not None
    assert auth_rule["defaultConfiguration"]["level"] == "warning"  # MEDIUM maps to warning


def test_sarif_severity_mapping():
    """Test severity levels are correctly mapped to SARIF levels."""
    reporter = SARIFReporter()
    findings = [
        Finding(
            rule_id="TEST001",
            rule_name="test-critical",
            severity=Severity.CRITICAL,
            message="Critical finding",
            file_path="test.py",
            line_number=1,
            column=0,
            code_snippet="code",
            fix_suggestion="",
            education="",
        ),
        Finding(
            rule_id="TEST002",
            rule_name="test-high",
            severity=Severity.HIGH,
            message="High finding",
            file_path="test.py",
            line_number=2,
            column=0,
            code_snippet="code",
            fix_suggestion="",
            education="",
        ),
        Finding(
            rule_id="TEST003",
            rule_name="test-medium",
            severity=Severity.MEDIUM,
            message="Medium finding",
            file_path="test.py",
            line_number=3,
            column=0,
            code_snippet="code",
            fix_suggestion="",
            education="",
        ),
        Finding(
            rule_id="TEST004",
            rule_name="test-low",
            severity=Severity.LOW,
            message="Low finding",
            file_path="test.py",
            line_number=4,
            column=0,
            code_snippet="code",
            fix_suggestion="",
            education="",
        ),
    ]
    result = ScanResult(files_scanned=1, findings=findings, scan_time_ms=10)

    output = reporter.render(result)
    sarif = json.loads(output)

    results = sarif["runs"][0]["results"]
    levels = {r["ruleId"]: r["level"] for r in results}

    assert levels["TEST001"] == "error"  # CRITICAL
    assert levels["TEST002"] == "error"  # HIGH
    assert levels["TEST003"] == "warning"  # MEDIUM
    assert levels["TEST004"] == "note"  # LOW


def test_sarif_empty_results():
    """Test SARIF output with no findings."""
    reporter = SARIFReporter()
    result = ScanResult(files_scanned=5, findings=[], scan_time_ms=50)

    output = reporter.render(result)
    sarif = json.loads(output)

    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_deduplicates_rules():
    """Test that rules are deduplicated when same rule has multiple findings."""
    reporter = SARIFReporter()
    findings = [
        Finding(
            rule_id="INJ001",
            rule_name="sql-injection",
            severity=Severity.CRITICAL,
            message="SQL injection in file1",
            file_path="file1.py",
            line_number=10,
            column=0,
            code_snippet="code1",
            fix_suggestion="",
            education="",
        ),
        Finding(
            rule_id="INJ001",
            rule_name="sql-injection",
            severity=Severity.CRITICAL,
            message="SQL injection in file2",
            file_path="file2.py",
            line_number=20,
            column=0,
            code_snippet="code2",
            fix_suggestion="",
            education="",
        ),
    ]
    result = ScanResult(files_scanned=2, findings=findings, scan_time_ms=10)

    output = reporter.render(result)
    sarif = json.loads(output)

    # Should have 2 results but only 1 rule definition
    assert len(sarif["runs"][0]["results"]) == 2
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1
