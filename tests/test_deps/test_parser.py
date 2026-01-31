"""Tests for dependency file parser."""

import json
from pathlib import Path

import pytest

from hackmenot.deps.parser import Dependency, DependencyParser


class TestParseRequirementsTxt:
    """Tests for parsing requirements.txt files."""

    def test_simple_package(self, tmp_path: Path) -> None:
        """Test parsing a simple package name without version."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests\n")

        parser = DependencyParser()
        deps = parser.parse_requirements_txt(req_file)

        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version is None
        assert deps[0].ecosystem == "pypi"
        assert deps[0].source_file == str(req_file)

    def test_with_exact_version(self, tmp_path: Path) -> None:
        """Test parsing package with exact version (==)."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.28.0\n")

        parser = DependencyParser()
        deps = parser.parse_requirements_txt(req_file)

        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "2.28.0"
        assert deps[0].ecosystem == "pypi"

    def test_with_version_range(self, tmp_path: Path) -> None:
        """Test parsing package with version range (>=)."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests>=2.20.0\n")

        parser = DependencyParser()
        deps = parser.parse_requirements_txt(req_file)

        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "2.20.0"

    def test_multiple_packages(self, tmp_path: Path) -> None:
        """Test parsing multiple packages."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.28.0\nflask>=2.0.0\nclick\n")

        parser = DependencyParser()
        deps = parser.parse_requirements_txt(req_file)

        assert len(deps) == 3
        assert deps[0].name == "requests"
        assert deps[0].version == "2.28.0"
        assert deps[1].name == "flask"
        assert deps[1].version == "2.0.0"
        assert deps[2].name == "click"
        assert deps[2].version is None

    def test_comments_and_blank_lines(self, tmp_path: Path) -> None:
        """Test that comments and blank lines are ignored."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("# This is a comment\nrequests==2.28.0\n\n# Another comment\nflask\n")

        parser = DependencyParser()
        deps = parser.parse_requirements_txt(req_file)

        assert len(deps) == 2
        assert deps[0].name == "requests"
        assert deps[1].name == "flask"

    def test_package_with_extras(self, tmp_path: Path) -> None:
        """Test parsing package with extras."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests[security]==2.28.0\n")

        parser = DependencyParser()
        deps = parser.parse_requirements_txt(req_file)

        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "2.28.0"

    def test_skip_flags(self, tmp_path: Path) -> None:
        """Test that lines starting with - are skipped."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("-r base.txt\n--index-url https://pypi.org/simple\nrequests\n")

        parser = DependencyParser()
        deps = parser.parse_requirements_txt(req_file)

        assert len(deps) == 1
        assert deps[0].name == "requests"


class TestParsePackageJson:
    """Tests for parsing package.json files."""

    def test_dependencies(self, tmp_path: Path) -> None:
        """Test parsing dependencies."""
        pkg_file = tmp_path / "package.json"
        pkg_file.write_text(json.dumps({
            "dependencies": {
                "express": "^4.18.0",
                "lodash": "~4.17.0"
            }
        }))

        parser = DependencyParser()
        deps = parser.parse_package_json(pkg_file)

        assert len(deps) == 2
        names = {d.name for d in deps}
        assert "express" in names
        assert "lodash" in names
        for dep in deps:
            assert dep.ecosystem == "npm"
            assert dep.source_file == str(pkg_file)

    def test_dev_dependencies(self, tmp_path: Path) -> None:
        """Test parsing devDependencies."""
        pkg_file = tmp_path / "package.json"
        pkg_file.write_text(json.dumps({
            "devDependencies": {
                "jest": "^29.0.0",
                "eslint": "^8.0.0"
            }
        }))

        parser = DependencyParser()
        deps = parser.parse_package_json(pkg_file)

        assert len(deps) == 2
        names = {d.name for d in deps}
        assert "jest" in names
        assert "eslint" in names

    def test_both_dependencies(self, tmp_path: Path) -> None:
        """Test parsing both dependencies and devDependencies."""
        pkg_file = tmp_path / "package.json"
        pkg_file.write_text(json.dumps({
            "dependencies": {
                "express": "^4.18.0"
            },
            "devDependencies": {
                "jest": "^29.0.0"
            }
        }))

        parser = DependencyParser()
        deps = parser.parse_package_json(pkg_file)

        assert len(deps) == 2
        names = {d.name for d in deps}
        assert "express" in names
        assert "jest" in names

    def test_version_stripping(self, tmp_path: Path) -> None:
        """Test that version prefixes are stripped."""
        pkg_file = tmp_path / "package.json"
        pkg_file.write_text(json.dumps({
            "dependencies": {
                "express": "^4.18.0",
                "lodash": "~4.17.0",
                "react": ">=18.0.0"
            }
        }))

        parser = DependencyParser()
        deps = parser.parse_package_json(pkg_file)

        versions = {d.name: d.version for d in deps}
        assert versions["express"] == "4.18.0"
        assert versions["lodash"] == "4.17.0"
        assert versions["react"] == "18.0.0"

    def test_invalid_json(self, tmp_path: Path) -> None:
        """Test handling invalid JSON."""
        pkg_file = tmp_path / "package.json"
        pkg_file.write_text("{ invalid json }")

        parser = DependencyParser()
        deps = parser.parse_package_json(pkg_file)

        assert len(deps) == 0

    def test_empty_dependencies(self, tmp_path: Path) -> None:
        """Test handling empty dependencies."""
        pkg_file = tmp_path / "package.json"
        pkg_file.write_text(json.dumps({
            "name": "test-package",
            "version": "1.0.0"
        }))

        parser = DependencyParser()
        deps = parser.parse_package_json(pkg_file)

        assert len(deps) == 0


class TestParsePyprojectToml:
    """Tests for parsing pyproject.toml files."""

    def test_dependencies_array(self, tmp_path: Path) -> None:
        """Test parsing dependencies array."""
        pyproject_file = tmp_path / "pyproject.toml"
        pyproject_file.write_text('''
[project]
name = "test-project"
dependencies = [
    "requests>=2.28.0",
    "click==8.1.0",
    "flask"
]
''')

        parser = DependencyParser()
        deps = parser.parse_pyproject_toml(pyproject_file)

        assert len(deps) == 3
        names = {d.name for d in deps}
        assert "requests" in names
        assert "click" in names
        assert "flask" in names
        for dep in deps:
            assert dep.ecosystem == "pypi"
            assert dep.source_file == str(pyproject_file)

    def test_dependencies_with_extras(self, tmp_path: Path) -> None:
        """Test parsing dependencies with extras."""
        pyproject_file = tmp_path / "pyproject.toml"
        pyproject_file.write_text('''
[project]
dependencies = [
    "requests[security]>=2.28.0"
]
''')

        parser = DependencyParser()
        deps = parser.parse_pyproject_toml(pyproject_file)

        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].version == "2.28.0"

    def test_no_dependencies(self, tmp_path: Path) -> None:
        """Test handling pyproject.toml without dependencies."""
        pyproject_file = tmp_path / "pyproject.toml"
        pyproject_file.write_text('''
[project]
name = "test-project"
version = "1.0.0"
''')

        parser = DependencyParser()
        deps = parser.parse_pyproject_toml(pyproject_file)

        assert len(deps) == 0


class TestParseDirectory:
    """Tests for auto-detecting and parsing dependency files."""

    def test_detect_requirements_txt(self, tmp_path: Path) -> None:
        """Test auto-detection of requirements.txt."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.28.0\n")

        parser = DependencyParser()
        deps = parser.parse_directory(tmp_path)

        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].ecosystem == "pypi"

    def test_detect_package_json(self, tmp_path: Path) -> None:
        """Test auto-detection of package.json."""
        pkg_file = tmp_path / "package.json"
        pkg_file.write_text(json.dumps({
            "dependencies": {
                "express": "^4.18.0"
            }
        }))

        parser = DependencyParser()
        deps = parser.parse_directory(tmp_path)

        assert len(deps) == 1
        assert deps[0].name == "express"
        assert deps[0].ecosystem == "npm"

    def test_detect_pyproject_toml(self, tmp_path: Path) -> None:
        """Test auto-detection of pyproject.toml."""
        pyproject_file = tmp_path / "pyproject.toml"
        pyproject_file.write_text('''
[project]
dependencies = [
    "flask>=2.0.0"
]
''')

        parser = DependencyParser()
        deps = parser.parse_directory(tmp_path)

        assert len(deps) == 1
        assert deps[0].name == "flask"
        assert deps[0].ecosystem == "pypi"

    def test_detect_multiple_files(self, tmp_path: Path) -> None:
        """Test auto-detection of multiple dependency files."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.28.0\n")

        pkg_file = tmp_path / "package.json"
        pkg_file.write_text(json.dumps({
            "dependencies": {
                "express": "^4.18.0"
            }
        }))

        parser = DependencyParser()
        deps = parser.parse_directory(tmp_path)

        assert len(deps) == 2
        ecosystems = {d.ecosystem for d in deps}
        assert "pypi" in ecosystems
        assert "npm" in ecosystems

    def test_empty_directory(self, tmp_path: Path) -> None:
        """Test parsing an empty directory."""
        parser = DependencyParser()
        deps = parser.parse_directory(tmp_path)

        assert len(deps) == 0


class TestDependencyDataclass:
    """Tests for the Dependency dataclass."""

    def test_create_dependency(self) -> None:
        """Test creating a Dependency instance."""
        dep = Dependency(
            name="requests",
            version="2.28.0",
            ecosystem="pypi",
            source_file="/path/to/requirements.txt"
        )

        assert dep.name == "requests"
        assert dep.version == "2.28.0"
        assert dep.ecosystem == "pypi"
        assert dep.source_file == "/path/to/requirements.txt"

    def test_dependency_equality(self) -> None:
        """Test Dependency equality comparison."""
        dep1 = Dependency(name="requests", version="2.28.0", ecosystem="pypi", source_file="/path")
        dep2 = Dependency(name="requests", version="2.28.0", ecosystem="pypi", source_file="/path")

        assert dep1 == dep2

    def test_dependency_with_none_version(self) -> None:
        """Test Dependency with None version."""
        dep = Dependency(name="requests", version=None, ecosystem="pypi", source_file="/path")

        assert dep.version is None
