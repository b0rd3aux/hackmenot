"""Tests for diff generator."""

import pytest
from io import StringIO
from rich.console import Console

from hackmenot.fixes.diff import FileDiff, DiffGenerator


class TestFileDiff:
    """Tests for FileDiff."""

    def test_has_changes_true(self):
        """Test has_changes returns True when content differs."""
        diff = FileDiff("test.py", "old", "new")
        assert diff.has_changes() is True

    def test_has_changes_false(self):
        """Test has_changes returns False when content is same."""
        diff = FileDiff("test.py", "same", "same")
        assert diff.has_changes() is False

    def test_unified_diff_output(self):
        """Test unified diff output format."""
        diff = FileDiff("test.py", "line1\nline2\n", "line1\nmodified\n")
        lines = diff.unified_diff()

        assert any("a/test.py" in line for line in lines)
        assert any("b/test.py" in line for line in lines)
        assert any("-line2" in line for line in lines)
        assert any("+modified" in line for line in lines)


class TestDiffGenerator:
    """Tests for DiffGenerator."""

    @pytest.fixture
    def generator(self):
        return DiffGenerator(console=Console(file=StringIO()))

    def test_generate_diffs_only_changed(self, generator):
        """Test that only changed files are included."""
        original = {"a.py": "old", "b.py": "same"}
        modified = {"a.py": "new", "b.py": "same"}

        diffs = generator.generate_diffs(original, modified)

        assert len(diffs) == 1
        assert diffs[0].file_path == "a.py"

    def test_generate_diffs_multiple_files(self, generator):
        """Test multiple changed files."""
        original = {"a.py": "old1", "b.py": "old2"}
        modified = {"a.py": "new1", "b.py": "new2"}

        diffs = generator.generate_diffs(original, modified)

        assert len(diffs) == 2

    def test_format_diff_plain(self, generator):
        """Test plain text diff output."""
        diffs = [FileDiff("test.py", "old\n", "new\n")]

        output = generator.format_diff_plain(diffs)

        assert "test.py" in output
        assert "-old" in output
        assert "+new" in output

    def test_empty_diffs(self, generator):
        """Test handling of no changes."""
        diffs = generator.generate_diffs({"a.py": "same"}, {"a.py": "same"})
        assert len(diffs) == 0
