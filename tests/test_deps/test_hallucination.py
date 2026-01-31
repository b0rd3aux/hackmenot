"""Tests for hallucination detection."""

import pytest

from hackmenot.core.models import Severity
from hackmenot.deps.hallucination import HallucinationDetector
from hackmenot.deps.parser import Dependency


class TestHallucinationDetector:
    """Tests for HallucinationDetector."""

    def test_known_package_not_flagged(self) -> None:
        """Test that known PyPI packages are not flagged."""
        detector = HallucinationDetector()
        dep = Dependency(
            name="requests",
            version="2.28.0",
            ecosystem="pypi",
            source_file="/path/to/requirements.txt",
        )

        finding = detector.check(dep)

        assert finding is None

    def test_unknown_package_flagged(self) -> None:
        """Test that unknown packages are flagged as DEP001."""
        detector = HallucinationDetector()
        dep = Dependency(
            name="fake-nonexistent-pkg",
            version="1.0.0",
            ecosystem="pypi",
            source_file="/path/to/requirements.txt",
        )

        finding = detector.check(dep)

        assert finding is not None
        assert finding.rule_id == "DEP001"
        assert finding.rule_name == "hallucinated-package"
        assert finding.severity == Severity.HIGH
        assert "fake-nonexistent-pkg" in finding.message
        assert "pypi" in finding.message
        assert finding.file_path == "/path/to/requirements.txt"

    def test_npm_known_package(self) -> None:
        """Test that known npm packages are not flagged."""
        detector = HallucinationDetector()
        dep = Dependency(
            name="lodash",
            version="4.17.21",
            ecosystem="npm",
            source_file="/path/to/package.json",
        )

        finding = detector.check(dep)

        assert finding is None

    def test_npm_unknown_package(self) -> None:
        """Test that unknown npm packages are flagged."""
        detector = HallucinationDetector()
        dep = Dependency(
            name="fake-npm-pkg",
            version="1.0.0",
            ecosystem="npm",
            source_file="/path/to/package.json",
        )

        finding = detector.check(dep)

        assert finding is not None
        assert finding.rule_id == "DEP001"
        assert finding.rule_name == "hallucinated-package"
        assert finding.severity == Severity.HIGH
        assert "fake-npm-pkg" in finding.message
        assert "npm" in finding.message

    def test_case_insensitive_matching(self) -> None:
        """Test that package matching is case-insensitive."""
        detector = HallucinationDetector()
        # "Requests" with capital R should match "requests"
        dep = Dependency(
            name="Requests",
            version="2.28.0",
            ecosystem="pypi",
            source_file="/path/to/requirements.txt",
        )

        finding = detector.check(dep)

        assert finding is None

    def test_unknown_ecosystem_returns_none(self) -> None:
        """Test that unknown ecosystems return None (no finding)."""
        detector = HallucinationDetector()
        dep = Dependency(
            name="some-package",
            version="1.0.0",
            ecosystem="cargo",  # unsupported ecosystem
            source_file="/path/to/Cargo.toml",
        )

        finding = detector.check(dep)

        assert finding is None

    def test_lazy_loading_pypi(self) -> None:
        """Test that PyPI packages are lazy-loaded."""
        detector = HallucinationDetector()

        # Before checking, internal state should be None
        assert detector._pypi_packages is None

        # After accessing the property, it should be loaded
        packages = detector.pypi_packages
        assert packages is not None
        assert isinstance(packages, set)
        assert "requests" in packages

    def test_lazy_loading_npm(self) -> None:
        """Test that npm packages are lazy-loaded."""
        detector = HallucinationDetector()

        # Before checking, internal state should be None
        assert detector._npm_packages is None

        # After accessing the property, it should be loaded
        packages = detector.npm_packages
        assert packages is not None
        assert isinstance(packages, set)
        assert "lodash" in packages

    def test_finding_code_snippet_with_version(self) -> None:
        """Test that code snippet includes version when available."""
        detector = HallucinationDetector()
        dep = Dependency(
            name="fake-pkg",
            version="1.2.3",
            ecosystem="pypi",
            source_file="/path/to/requirements.txt",
        )

        finding = detector.check(dep)

        assert finding is not None
        assert finding.code_snippet == "fake-pkg==1.2.3"

    def test_finding_code_snippet_without_version(self) -> None:
        """Test that code snippet shows only name when no version."""
        detector = HallucinationDetector()
        dep = Dependency(
            name="fake-pkg",
            version=None,
            ecosystem="pypi",
            source_file="/path/to/requirements.txt",
        )

        finding = detector.check(dep)

        assert finding is not None
        assert finding.code_snippet == "fake-pkg"
