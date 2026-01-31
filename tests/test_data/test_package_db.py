"""Tests for package database loading."""

import pytest

from hackmenot.data import load_package_set


class TestLoadPackageSet:
    """Tests for the load_package_set function."""

    def test_load_pypi_packages(self):
        """Test loading PyPI package list."""
        packages = load_package_set("pypi")
        assert isinstance(packages, set)
        assert len(packages) >= 100
        # Check some known packages are present
        assert "requests" in packages
        assert "numpy" in packages
        assert "pandas" in packages
        assert "django" in packages
        assert "flask" in packages

    def test_load_npm_packages(self):
        """Test loading npm package list."""
        packages = load_package_set("npm")
        assert isinstance(packages, set)
        assert len(packages) >= 90
        # Check some known packages are present
        assert "lodash" in packages
        assert "express" in packages
        assert "react" in packages
        assert "webpack" in packages
        assert "typescript" in packages

    def test_case_insensitive_ecosystem(self):
        """Test that ecosystem name is case-insensitive."""
        pypi_lower = load_package_set("pypi")
        pypi_upper = load_package_set("PYPI")
        pypi_mixed = load_package_set("PyPI")
        assert pypi_lower == pypi_upper == pypi_mixed

    def test_unknown_ecosystem_returns_empty_set(self):
        """Test that unknown ecosystem returns empty set."""
        packages = load_package_set("unknown_ecosystem")
        assert packages == set()
        assert isinstance(packages, set)

    def test_packages_are_lowercase(self):
        """Test that all package names are lowercase."""
        pypi_packages = load_package_set("pypi")
        npm_packages = load_package_set("npm")

        for pkg in pypi_packages:
            assert pkg == pkg.lower(), f"Package {pkg} is not lowercase"

        for pkg in npm_packages:
            assert pkg == pkg.lower(), f"Package {pkg} is not lowercase"
