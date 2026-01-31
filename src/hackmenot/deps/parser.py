"""Parser for dependency files."""

import json
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Dependency:
    """A parsed dependency."""

    name: str
    version: str | None
    ecosystem: str  # "pypi" or "npm"
    source_file: str


class DependencyParser:
    """Parser for various dependency file formats."""

    def parse_directory(self, directory: Path) -> list[Dependency]:
        """Auto-detect and parse all dependency files in a directory."""
        deps: list[Dependency] = []

        req_txt = directory / "requirements.txt"
        if req_txt.exists():
            deps.extend(self.parse_requirements_txt(req_txt))

        pyproject = directory / "pyproject.toml"
        if pyproject.exists():
            deps.extend(self.parse_pyproject_toml(pyproject))

        pkg_json = directory / "package.json"
        if pkg_json.exists():
            deps.extend(self.parse_package_json(pkg_json))

        return deps

    def parse_requirements_txt(self, filepath: Path) -> list[Dependency]:
        """Parse requirements.txt file."""
        deps = []
        for line in filepath.read_text().strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(r"^([a-zA-Z0-9_-]+)(?:\[.*?\])?(?:[=<>!~]+(.+))?$", line)
            if match:
                name = match.group(1).lower()
                version = match.group(2)
                deps.append(
                    Dependency(
                        name=name,
                        version=version,
                        ecosystem="pypi",
                        source_file=str(filepath),
                    )
                )
        return deps

    def parse_package_json(self, filepath: Path) -> list[Dependency]:
        """Parse package.json file."""
        deps = []
        try:
            data = json.loads(filepath.read_text())
        except json.JSONDecodeError:
            return deps
        for dep_type in ["dependencies", "devDependencies"]:
            for name, version_spec in data.get(dep_type, {}).items():
                version = re.sub(r"^[\^~>=<]+", "", version_spec)
                deps.append(
                    Dependency(
                        name=name.lower(),
                        version=version if version else None,
                        ecosystem="npm",
                        source_file=str(filepath),
                    )
                )
        return deps

    def parse_pyproject_toml(self, filepath: Path) -> list[Dependency]:
        """Parse pyproject.toml file."""
        deps = []
        content = filepath.read_text()
        # Match dependencies array, handling nested brackets in extras like [security]
        match = re.search(r"dependencies\s*=\s*\[((?:[^\]]|\][^\n])*)\]", content, re.DOTALL)
        if match:
            deps_str = match.group(1)
            for pkg_match in re.finditer(r'"([^"]+)"', deps_str):
                pkg_spec = pkg_match.group(1)
                name_match = re.match(
                    r"^([a-zA-Z0-9_.-]+)(?:\[.*?\])?(?:[=<>!~]+(.+))?$", pkg_spec
                )
                if name_match:
                    deps.append(
                        Dependency(
                            name=name_match.group(1).lower(),
                            version=name_match.group(2),
                            ecosystem="pypi",
                            source_file=str(filepath),
                        )
                    )
        return deps
