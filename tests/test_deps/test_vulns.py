"""Tests for OSV vulnerability checking."""

import json
from io import BytesIO
from unittest.mock import MagicMock, patch
from urllib.error import URLError

import pytest

from hackmenot.core.models import Severity
from hackmenot.deps.parser import Dependency
from hackmenot.deps.vulns import OSVClient


class TestOSVClient:
    """Tests for OSVClient."""

    def test_check_no_vulnerabilities(self) -> None:
        """Test that empty vulns response returns no findings."""
        client = OSVClient()
        dep = Dependency(
            name="requests",
            version="2.28.0",
            ecosystem="pypi",
            source_file="/path/to/requirements.txt",
        )

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"vulns": []}).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            findings = client.check(dep)

        assert findings == []

    def test_check_with_vulnerability(self) -> None:
        """Test that vuln response creates DEP003 finding."""
        client = OSVClient()
        dep = Dependency(
            name="requests",
            version="2.25.0",
            ecosystem="pypi",
            source_file="/path/to/requirements.txt",
        )

        vuln_response = {
            "vulns": [
                {
                    "id": "CVE-2023-12345",
                    "summary": "Security vulnerability in requests",
                    "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                    "affected": [
                        {
                            "ranges": [
                                {
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "2.28.0"},
                                    ]
                                }
                            ]
                        }
                    ],
                }
            ]
        }

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(vuln_response).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            findings = client.check(dep)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.rule_id == "DEP003"
        assert finding.rule_name == "vulnerable-dependency"
        assert finding.severity == Severity.HIGH
        assert "CVE-2023-12345" in finding.message
        assert "requests@2.25.0" in finding.message
        assert finding.file_path == "/path/to/requirements.txt"
        assert finding.fix_suggestion == "Upgrade to version 2.28.0"
        assert finding.code_snippet == "requests==2.25.0"

    def test_network_error_returns_empty(self) -> None:
        """Test that network errors return empty list."""
        client = OSVClient()
        dep = Dependency(
            name="requests",
            version="2.28.0",
            ecosystem="pypi",
            source_file="/path/to/requirements.txt",
        )

        with patch("urllib.request.urlopen", side_effect=URLError("Network error")):
            findings = client.check(dep)

        assert findings == []

    def test_timeout_error_returns_empty(self) -> None:
        """Test that timeout errors return empty list."""
        client = OSVClient()
        dep = Dependency(
            name="requests",
            version="2.28.0",
            ecosystem="pypi",
            source_file="/path/to/requirements.txt",
        )

        with patch("urllib.request.urlopen", side_effect=TimeoutError("Timeout")):
            findings = client.check(dep)

        assert findings == []

    def test_batch_check(self) -> None:
        """Test batch checking multiple dependencies."""
        client = OSVClient()
        deps = [
            Dependency(
                name="requests",
                version="2.25.0",
                ecosystem="pypi",
                source_file="/path/to/requirements.txt",
            ),
            Dependency(
                name="flask",
                version="1.0.0",
                ecosystem="pypi",
                source_file="/path/to/requirements.txt",
            ),
        ]

        batch_response = {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "CVE-2023-11111",
                            "summary": "Requests vuln",
                            "severity": [{"type": "CVSS_V3", "score": "5.0"}],
                            "affected": [],
                        }
                    ]
                },
                {
                    "vulns": [
                        {
                            "id": "CVE-2023-22222",
                            "summary": "Flask vuln",
                            "severity": [{"type": "CVSS_V3", "score": "9.5"}],
                            "affected": [],
                        }
                    ]
                },
            ]
        }

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(batch_response).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            findings = client.check_batch(deps)

        assert len(findings) == 2
        assert findings[0].rule_id == "DEP003"
        assert "CVE-2023-11111" in findings[0].message
        assert "requests" in findings[0].message
        assert findings[0].severity == Severity.MEDIUM  # 5.0 CVSS

        assert findings[1].rule_id == "DEP003"
        assert "CVE-2023-22222" in findings[1].message
        assert "flask" in findings[1].message
        assert findings[1].severity == Severity.CRITICAL  # 9.5 CVSS

    def test_no_version_skipped(self) -> None:
        """Test that dependencies without version are skipped."""
        client = OSVClient()
        dep = Dependency(
            name="requests",
            version=None,
            ecosystem="pypi",
            source_file="/path/to/requirements.txt",
        )

        findings = client.check(dep)

        assert findings == []

    def test_batch_no_version_skipped(self) -> None:
        """Test that batch check skips deps without version."""
        client = OSVClient()
        deps = [
            Dependency(
                name="requests",
                version=None,
                ecosystem="pypi",
                source_file="/path/to/requirements.txt",
            ),
            Dependency(
                name="flask",
                version=None,
                ecosystem="pypi",
                source_file="/path/to/requirements.txt",
            ),
        ]

        # Should not even make a network request
        with patch("urllib.request.urlopen") as mock_urlopen:
            findings = client.check_batch(deps)

        assert findings == []
        mock_urlopen.assert_not_called()

    def test_severity_mapping_critical(self) -> None:
        """Test CVSS score >= 9.0 maps to CRITICAL."""
        client = OSVClient()
        assert client._severity_from_cvss(9.0) == Severity.CRITICAL
        assert client._severity_from_cvss(10.0) == Severity.CRITICAL

    def test_severity_mapping_high(self) -> None:
        """Test CVSS score >= 7.0 and < 9.0 maps to HIGH."""
        client = OSVClient()
        assert client._severity_from_cvss(7.0) == Severity.HIGH
        assert client._severity_from_cvss(8.9) == Severity.HIGH

    def test_severity_mapping_medium(self) -> None:
        """Test CVSS score >= 4.0 and < 7.0 maps to MEDIUM."""
        client = OSVClient()
        assert client._severity_from_cvss(4.0) == Severity.MEDIUM
        assert client._severity_from_cvss(6.9) == Severity.MEDIUM

    def test_severity_mapping_low(self) -> None:
        """Test CVSS score < 4.0 maps to LOW."""
        client = OSVClient()
        assert client._severity_from_cvss(0.0) == Severity.LOW
        assert client._severity_from_cvss(3.9) == Severity.LOW

    def test_ecosystem_name_pypi(self) -> None:
        """Test ecosystem name conversion for PyPI."""
        client = OSVClient()
        assert client._ecosystem_name("pypi") == "PyPI"

    def test_ecosystem_name_npm(self) -> None:
        """Test ecosystem name conversion for npm."""
        client = OSVClient()
        assert client._ecosystem_name("npm") == "npm"

    def test_ecosystem_name_unknown(self) -> None:
        """Test ecosystem name for unknown ecosystem passes through."""
        client = OSVClient()
        assert client._ecosystem_name("cargo") == "cargo"

    def test_vuln_without_fix_version(self) -> None:
        """Test vuln without fix version suggests checking for patches."""
        client = OSVClient()
        dep = Dependency(
            name="requests",
            version="2.25.0",
            ecosystem="pypi",
            source_file="/path/to/requirements.txt",
        )

        vuln_response = {
            "vulns": [
                {
                    "id": "CVE-2023-12345",
                    "summary": "Security vulnerability",
                    "affected": [],  # No fix version
                }
            ]
        }

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(vuln_response).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            findings = client.check(dep)

        assert len(findings) == 1
        assert findings[0].fix_suggestion == "Check for patches"

    def test_json_decode_error_returns_empty(self) -> None:
        """Test that invalid JSON response returns empty list."""
        client = OSVClient()
        dep = Dependency(
            name="requests",
            version="2.28.0",
            ecosystem="pypi",
            source_file="/path/to/requirements.txt",
        )

        mock_response = MagicMock()
        mock_response.read.return_value = b"invalid json"
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            findings = client.check(dep)

        assert findings == []

    def test_default_severity_when_no_cvss(self) -> None:
        """Test default MEDIUM severity when no CVSS score provided."""
        client = OSVClient()
        dep = Dependency(
            name="requests",
            version="2.25.0",
            ecosystem="pypi",
            source_file="/path/to/requirements.txt",
        )

        vuln_response = {
            "vulns": [
                {
                    "id": "CVE-2023-12345",
                    "summary": "Security vulnerability",
                    "severity": [],  # No severity info
                    "affected": [],
                }
            ]
        }

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(vuln_response).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            findings = client.check(dep)

        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
