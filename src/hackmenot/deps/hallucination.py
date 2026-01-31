"""Hallucination detection for dependencies."""

from hackmenot.core.models import Finding, Severity
from hackmenot.data import load_package_set
from hackmenot.deps.parser import Dependency


class HallucinationDetector:
    """Detect potentially hallucinated (non-existent) packages."""

    def __init__(self) -> None:
        self._pypi_packages: set[str] | None = None
        self._npm_packages: set[str] | None = None

    @property
    def pypi_packages(self) -> set[str]:
        """Lazy-load PyPI package set."""
        if self._pypi_packages is None:
            self._pypi_packages = load_package_set("pypi")
        return self._pypi_packages

    @property
    def npm_packages(self) -> set[str]:
        """Lazy-load npm package set."""
        if self._npm_packages is None:
            self._npm_packages = load_package_set("npm")
        return self._npm_packages

    def check(self, dep: Dependency) -> Finding | None:
        """Check if a dependency might be hallucinated.

        Returns a Finding if package not in known list, None otherwise.
        """
        name_lower = dep.name.lower()

        if dep.ecosystem == "pypi":
            packages = self.pypi_packages
        elif dep.ecosystem == "npm":
            packages = self.npm_packages
        else:
            return None

        if not packages:
            return None

        if name_lower not in packages:
            return Finding(
                rule_id="DEP001",
                rule_name="hallucinated-package",
                severity=Severity.HIGH,
                message=f"Package '{dep.name}' not found in {dep.ecosystem} registry. May be hallucinated by AI.",
                file_path=dep.source_file,
                line_number=0,
                column=0,
                code_snippet=f"{dep.name}=={dep.version}" if dep.version else dep.name,
                fix_suggestion="Verify this package exists on PyPI or npm before using it.",
                education="AI assistants sometimes invent package names that don't exist. Always verify dependencies.",
            )

        return None
