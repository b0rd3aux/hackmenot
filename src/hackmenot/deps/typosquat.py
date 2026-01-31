"""Typosquat detection for dependencies."""

from hackmenot.core.models import Finding, Severity
from hackmenot.deps.parser import Dependency


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


# Popular packages to check against (top ~100)
POPULAR_PYPI = {
    "requests", "numpy", "pandas", "boto3", "urllib3", "setuptools",
    "typing-extensions", "botocore", "certifi", "idna", "charset-normalizer",
    "python-dateutil", "pip", "pyyaml", "packaging", "s3transfer",
    "six", "cryptography", "cffi", "wheel", "pycparser", "jmespath",
    "pytz", "attrs", "click", "importlib-metadata", "zipp", "platformdirs",
    "filelock", "colorama", "virtualenv", "awscli", "pillow", "protobuf",
    "jinja2", "markupsafe", "rsa", "pyasn1", "docutils", "grpcio",
    "scipy", "google-api-core", "fsspec", "tomli", "pyparsing", "aiohttp",
    "flask", "django", "fastapi", "sqlalchemy", "pytest", "selenium",
}

POPULAR_NPM = {
    "lodash", "chalk", "request", "commander", "express", "debug",
    "async", "bluebird", "moment", "react", "underscore", "uuid",
    "glob", "minimist", "mkdirp", "colors", "yargs", "through2",
    "semver", "readable-stream", "prop-types", "rxjs", "ws", "inherits",
    "typescript", "webpack", "axios", "babel-runtime", "fs-extra",
    "inquirer", "cheerio", "dotenv", "body-parser", "classnames",
    "eslint", "jest", "mocha", "chai", "sinon", "gulp", "grunt",
    "react-dom", "redux", "vue", "angular", "jquery", "bootstrap",
}


class TyposquatDetector:
    """Detect potential typosquatting attacks in dependencies."""

    MAX_DISTANCE = 2

    def check(self, dep: Dependency) -> Finding | None:
        """Check if dependency might be a typosquat.

        Returns Finding if name is within edit distance 2 of popular package.
        """
        name_lower = dep.name.lower()

        if dep.ecosystem == "pypi":
            popular = POPULAR_PYPI
        elif dep.ecosystem == "npm":
            popular = POPULAR_NPM
        else:
            return None

        # Don't flag exact matches
        if name_lower in popular:
            return None

        # Check distance to each popular package
        for popular_pkg in popular:
            distance = levenshtein_distance(name_lower, popular_pkg)
            if 0 < distance <= self.MAX_DISTANCE:
                return Finding(
                    rule_id="DEP002",
                    rule_name="typosquat-package",
                    severity=Severity.CRITICAL,
                    message=f"Package '{dep.name}' is similar to '{popular_pkg}'. Possible typosquatting attack.",
                    file_path=dep.source_file,
                    line_number=0,
                    column=0,
                    code_snippet=f"{dep.name}=={dep.version}" if dep.version else dep.name,
                    fix_suggestion=f"Did you mean '{popular_pkg}'? Verify the package name.",
                    education="Typosquatting is when attackers publish malicious packages with names similar to popular ones.",
                )

        return None
