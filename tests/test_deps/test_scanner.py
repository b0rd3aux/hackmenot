"""Tests for dependency scanner."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from hackmenot.core.models import Severity
from hackmenot.deps.scanner import DependencyScanner


class TestDependencyScanner:
    """Tests for the DependencyScanner class."""

    def test_scan_finds_hallucinated_package(self, tmp_path: Path) -> None:
        """Test that scanner detects hallucinated packages."""
        req_file = tmp_path / "requirements.txt"
        # Use a package name that won't be in the package list
        req_file.write_text("definitely-fake-nonexistent-package==1.0.0\n")

        scanner = DependencyScanner()
        result = scanner.scan(tmp_path)

        assert result.files_scanned == 1
        assert len(result.findings) >= 1
        # Check for hallucination finding
        hallucination_findings = [f for f in result.findings if f.rule_id == "DEP001"]
        assert len(hallucination_findings) == 1
        assert "definitely-fake-nonexistent-package" in hallucination_findings[0].message
        assert hallucination_findings[0].severity == Severity.HIGH

    def test_scan_finds_typosquat(self, tmp_path: Path) -> None:
        """Test that scanner detects typosquat packages."""
        req_file = tmp_path / "requirements.txt"
        # "reqeusts" is a typosquat of "requests" (transposed letters)
        req_file.write_text("reqeusts==2.28.0\n")

        # Mock the hallucination detector to say the package exists
        # so the typosquat check runs
        scanner = DependencyScanner()
        with patch.object(scanner.hallucination_detector, 'check', return_value=None):
            result = scanner.scan(tmp_path)

        assert result.files_scanned == 1
        assert len(result.findings) >= 1
        typosquat_findings = [f for f in result.findings if f.rule_id == "DEP002"]
        assert len(typosquat_findings) == 1
        assert "reqeusts" in typosquat_findings[0].message
        assert "requests" in typosquat_findings[0].message
        assert typosquat_findings[0].severity == Severity.CRITICAL

    def test_scan_clean_dependencies(self, tmp_path: Path) -> None:
        """Test that scanner returns no findings for clean dependencies."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.28.0\nflask>=2.0.0\n")

        scanner = DependencyScanner()
        # Mock both detectors to return no findings
        with patch.object(scanner.hallucination_detector, 'check', return_value=None):
            with patch.object(scanner.typosquat_detector, 'check', return_value=None):
                result = scanner.scan(tmp_path)

        assert result.files_scanned == 1
        assert len(result.findings) == 0
        assert result.scan_time_ms >= 0

    def test_scan_no_dependency_files(self, tmp_path: Path) -> None:
        """Test scanning a directory with no dependency files."""
        # Create an empty directory (tmp_path is already empty)
        scanner = DependencyScanner()
        result = scanner.scan(tmp_path)

        assert result.files_scanned == 0
        assert len(result.findings) == 0
        assert result.scan_time_ms >= 0

    def test_scan_mixed_ecosystems(self, tmp_path: Path) -> None:
        """Test scanning directory with both Python and npm dependencies."""
        # Create requirements.txt
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("fake-python-pkg==1.0.0\n")

        # Create package.json
        pkg_file = tmp_path / "package.json"
        pkg_file.write_text(json.dumps({
            "dependencies": {
                "fake-npm-pkg": "^1.0.0"
            }
        }))

        scanner = DependencyScanner()
        result = scanner.scan(tmp_path)

        # Both files should be scanned
        assert result.files_scanned == 2
        # Both fake packages should be flagged as hallucinated
        hallucination_findings = [f for f in result.findings if f.rule_id == "DEP001"]
        assert len(hallucination_findings) == 2

    def test_scan_skips_typosquat_for_hallucinated(self, tmp_path: Path) -> None:
        """Test that typosquat check is skipped for hallucinated packages."""
        req_file = tmp_path / "requirements.txt"
        # This could be both hallucinated and a typosquat, but hallucination should be primary
        req_file.write_text("reqeusts==1.0.0\n")  # typosquat of requests

        scanner = DependencyScanner()
        # Don't mock - let hallucination detector run
        # If package is hallucinated, typosquat should not be checked
        result = scanner.scan(tmp_path)

        # Should only have hallucination finding, not both
        assert len(result.findings) == 1
        assert result.findings[0].rule_id == "DEP001"

    def test_scan_with_vulns_disabled(self, tmp_path: Path) -> None:
        """Test that vulnerability check is disabled by default."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.28.0\n")

        scanner = DependencyScanner()
        with patch.object(scanner.hallucination_detector, 'check', return_value=None):
            with patch.object(scanner.typosquat_detector, 'check', return_value=None):
                with patch.object(scanner.osv_client, 'check_batch') as mock_osv:
                    result = scanner.scan(tmp_path, check_vulns=False)

        # OSV client should not be called when check_vulns is False
        mock_osv.assert_not_called()
        assert len(result.findings) == 0

    def test_scan_with_vulns_enabled(self, tmp_path: Path) -> None:
        """Test that vulnerability check is called when enabled."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.28.0\n")

        scanner = DependencyScanner()
        with patch.object(scanner.hallucination_detector, 'check', return_value=None):
            with patch.object(scanner.typosquat_detector, 'check', return_value=None):
                with patch.object(scanner.osv_client, 'check_batch', return_value=[]) as mock_osv:
                    result = scanner.scan(tmp_path, check_vulns=True)

        # OSV client should be called when check_vulns is True
        mock_osv.assert_called_once()
        assert len(result.findings) == 0

    def test_scan_returns_scan_result(self, tmp_path: Path) -> None:
        """Test that scan returns a proper ScanResult object."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.28.0\n")

        scanner = DependencyScanner()
        with patch.object(scanner.hallucination_detector, 'check', return_value=None):
            with patch.object(scanner.typosquat_detector, 'check', return_value=None):
                result = scanner.scan(tmp_path)

        # Check ScanResult properties
        assert hasattr(result, 'files_scanned')
        assert hasattr(result, 'findings')
        assert hasattr(result, 'scan_time_ms')
        assert isinstance(result.files_scanned, int)
        assert isinstance(result.findings, list)
        assert isinstance(result.scan_time_ms, float)

    def test_scanner_initialization(self) -> None:
        """Test that scanner initializes all components."""
        scanner = DependencyScanner()

        assert scanner.parser is not None
        assert scanner.hallucination_detector is not None
        assert scanner.typosquat_detector is not None
        assert scanner.osv_client is not None
