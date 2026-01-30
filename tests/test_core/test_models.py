"""Tests for core data models."""

from hackmenot.core.models import Finding, Rule, ScanResult, Severity


def test_severity_ordering():
    """Test severity levels are ordered correctly."""
    assert Severity.CRITICAL > Severity.HIGH
    assert Severity.HIGH > Severity.MEDIUM
    assert Severity.MEDIUM > Severity.LOW


def test_finding_creation():
    """Test Finding dataclass creation."""
    finding = Finding(
        rule_id="AUTH001",
        rule_name="missing-auth",
        severity=Severity.HIGH,
        message="Missing authentication",
        file_path="src/api.py",
        line_number=42,
        column=0,
        code_snippet="def get_user():",
        fix_suggestion="Add @login_required decorator",
        education="AI often skips auth checks",
    )
    assert finding.rule_id == "AUTH001"
    assert finding.severity == Severity.HIGH
    assert finding.line_number == 42


def test_rule_creation():
    """Test Rule dataclass creation."""
    rule = Rule(
        id="AUTH001",
        name="missing-auth",
        severity=Severity.HIGH,
        category="authentication",
        languages=["python"],
        description="Missing authentication decorator",
        message="Endpoint missing auth",
        pattern={"type": "ast"},
        fix_template="@login_required\n{original}",
        education="AI skips auth",
    )
    assert rule.id == "AUTH001"
    assert "python" in rule.languages


def test_scan_result_summary():
    """Test ScanResult computes summary correctly."""
    findings = [
        Finding(
            rule_id="A", rule_name="a", severity=Severity.CRITICAL,
            message="m", file_path="f", line_number=1, column=0,
            code_snippet="c", fix_suggestion="", education="",
        ),
        Finding(
            rule_id="B", rule_name="b", severity=Severity.HIGH,
            message="m", file_path="f", line_number=2, column=0,
            code_snippet="c", fix_suggestion="", education="",
        ),
        Finding(
            rule_id="C", rule_name="c", severity=Severity.HIGH,
            message="m", file_path="f", line_number=3, column=0,
            code_snippet="c", fix_suggestion="", education="",
        ),
    ]
    result = ScanResult(files_scanned=10, findings=findings, scan_time_ms=100)

    summary = result.summary_by_severity()
    assert summary[Severity.CRITICAL] == 1
    assert summary[Severity.HIGH] == 2
    assert summary[Severity.MEDIUM] == 0
