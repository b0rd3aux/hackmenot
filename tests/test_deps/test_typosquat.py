"""Tests for typosquat detection."""

import pytest

from hackmenot.core.models import Severity
from hackmenot.deps.parser import Dependency
from hackmenot.deps.typosquat import TyposquatDetector, levenshtein_distance


class TestLevenshteinDistance:
    """Tests for the Levenshtein distance algorithm."""

    def test_levenshtein_distance_basic(self):
        """Verify algorithm works correctly."""
        # Same strings
        assert levenshtein_distance("hello", "hello") == 0

        # One character difference
        assert levenshtein_distance("hello", "hallo") == 1

        # Deletion
        assert levenshtein_distance("hello", "helo") == 1

        # Insertion
        assert levenshtein_distance("hello", "helllo") == 1

        # Multiple differences
        assert levenshtein_distance("kitten", "sitting") == 3

        # Empty strings
        assert levenshtein_distance("", "") == 0
        assert levenshtein_distance("abc", "") == 3
        assert levenshtein_distance("", "abc") == 3

    def test_levenshtein_distance_symmetric(self):
        """Distance should be symmetric."""
        assert levenshtein_distance("abc", "def") == levenshtein_distance("def", "abc")
        assert levenshtein_distance("requests", "requets") == levenshtein_distance(
            "requets", "requests"
        )


class TestTyposquatDetector:
    """Tests for the TyposquatDetector class."""

    @pytest.fixture
    def detector(self):
        """Create a detector instance."""
        return TyposquatDetector()

    def test_exact_match_not_flagged(self, detector):
        """Exact match of popular package should not be flagged."""
        dep = Dependency(
            name="requests",
            version="2.28.0",
            ecosystem="pypi",
            source_file="requirements.txt",
        )
        finding = detector.check(dep)
        assert finding is None

    def test_typo_flagged(self, detector):
        """Typo of popular package should be flagged."""
        dep = Dependency(
            name="requets",  # Missing 's'
            version="1.0.0",
            ecosystem="pypi",
            source_file="requirements.txt",
        )
        finding = detector.check(dep)
        assert finding is not None
        assert finding.rule_id == "DEP002"
        assert finding.rule_name == "typosquat-package"
        assert finding.severity == Severity.CRITICAL
        assert "requets" in finding.message
        assert "requests" in finding.message
        assert "requests" in finding.fix_suggestion

    def test_npm_typo_flagged(self, detector):
        """Typo of popular npm package should be flagged."""
        dep = Dependency(
            name="lodashe",  # Extra 'e'
            version="4.17.21",
            ecosystem="npm",
            source_file="package.json",
        )
        finding = detector.check(dep)
        assert finding is not None
        assert finding.rule_id == "DEP002"
        assert "lodashe" in finding.message
        assert "lodash" in finding.message

    def test_distant_name_not_flagged(self, detector):
        """Package name with large edit distance should not be flagged."""
        dep = Dependency(
            name="mycompanylib",
            version="1.0.0",
            ecosystem="pypi",
            source_file="requirements.txt",
        )
        finding = detector.check(dep)
        assert finding is None

    def test_levenshtein_distance_threshold(self, detector):
        """Package with distance > 2 should not be flagged."""
        dep = Dependency(
            name="requxxxx",  # Distance 4 from 'requests'
            version="1.0.0",
            ecosystem="pypi",
            source_file="requirements.txt",
        )
        finding = detector.check(dep)
        assert finding is None

    def test_unknown_ecosystem_not_flagged(self, detector):
        """Unknown ecosystem should not be flagged."""
        dep = Dependency(
            name="requests",
            version="1.0.0",
            ecosystem="cargo",  # Unknown ecosystem
            source_file="Cargo.toml",
        )
        finding = detector.check(dep)
        assert finding is None

    def test_case_insensitive(self, detector):
        """Detection should be case insensitive."""
        dep = Dependency(
            name="Requets",  # Mixed case typo
            version="1.0.0",
            ecosystem="pypi",
            source_file="requirements.txt",
        )
        finding = detector.check(dep)
        assert finding is not None
        assert "requests" in finding.message.lower()

    def test_finding_contains_education(self, detector):
        """Finding should contain educational information."""
        dep = Dependency(
            name="requets",
            version="1.0.0",
            ecosystem="pypi",
            source_file="requirements.txt",
        )
        finding = detector.check(dep)
        assert finding is not None
        assert "typosquatting" in finding.education.lower()

    def test_finding_contains_code_snippet(self, detector):
        """Finding should contain code snippet."""
        dep = Dependency(
            name="requets",
            version="1.0.0",
            ecosystem="pypi",
            source_file="requirements.txt",
        )
        finding = detector.check(dep)
        assert finding is not None
        assert "requets==1.0.0" in finding.code_snippet

    def test_code_snippet_without_version(self, detector):
        """Code snippet should handle missing version."""
        dep = Dependency(
            name="requets",
            version=None,
            ecosystem="pypi",
            source_file="requirements.txt",
        )
        finding = detector.check(dep)
        assert finding is not None
        assert finding.code_snippet == "requets"
