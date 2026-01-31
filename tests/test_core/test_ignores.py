"""Tests for IgnoreHandler inline ignore comments."""

import pytest

from hackmenot.core.ignores import IgnoreHandler


class TestParseSingleLineIgnore:
    """Tests for parsing same-line ignore comments."""

    def test_parse_single_line_ignore_basic(self):
        """Parse # hackmenot:ignore[RULE] - reason on same line."""
        source = 'password = "secret123"  # hackmenot:ignore[SEC001] - test credentials'
        handler = IgnoreHandler()
        ignores = handler.parse(source)

        assert (1, "SEC001") in ignores

    def test_parse_single_line_ignore_various_spacing(self):
        """Parse ignore comment with various spacing."""
        source = 'x = 1  #hackmenot:ignore[AUTH001] - some reason here'
        handler = IgnoreHandler()
        ignores = handler.parse(source)

        assert (1, "AUTH001") in ignores

    def test_parse_multiple_same_line_ignores(self):
        """Parse multiple same-line ignores in different lines."""
        source = """line1  # hackmenot:ignore[SEC001] - reason1
line2
line3  # hackmenot:ignore[AUTH002] - reason2
"""
        handler = IgnoreHandler()
        ignores = handler.parse(source)

        assert (1, "SEC001") in ignores
        assert (3, "AUTH002") in ignores
        assert len(ignores) == 2


class TestParseNextLineIgnore:
    """Tests for parsing next-line ignore comments."""

    def test_parse_next_line_ignore_basic(self):
        """Parse # hackmenot:ignore-next-line[RULE] - reason."""
        source = """# hackmenot:ignore-next-line[SEC001] - test credentials
password = "secret123"
"""
        handler = IgnoreHandler()
        ignores = handler.parse(source)

        # The ignore applies to line 2 (the next line after the comment)
        assert (2, "SEC001") in ignores

    def test_parse_next_line_ignore_indented(self):
        """Parse indented next-line ignore comment."""
        source = """def func():
    # hackmenot:ignore-next-line[AUTH001] - known limitation
    insecure_call()
"""
        handler = IgnoreHandler()
        ignores = handler.parse(source)

        assert (3, "AUTH001") in ignores

    def test_parse_multiple_next_line_ignores(self):
        """Parse multiple next-line ignores."""
        source = """# hackmenot:ignore-next-line[SEC001] - reason1
line1
normal line
# hackmenot:ignore-next-line[AUTH002] - reason2
line2
"""
        handler = IgnoreHandler()
        ignores = handler.parse(source)

        assert (2, "SEC001") in ignores
        assert (5, "AUTH002") in ignores


class TestParseFileIgnore:
    """Tests for parsing file-level ignore comments."""

    def test_parse_file_ignore_basic(self):
        """Parse # hackmenot:ignore-file - reason."""
        source = """# hackmenot:ignore-file - this file is for testing purposes
def some_code():
    pass
"""
        handler = IgnoreHandler()
        handler.parse(source)

        assert handler.is_file_ignored() is True

    def test_parse_file_ignore_not_at_start(self):
        """File ignore comment works even if not at file start."""
        source = """# Some header comment
# hackmenot:ignore-file - test file
code here
"""
        handler = IgnoreHandler()
        handler.parse(source)

        assert handler.is_file_ignored() is True

    def test_file_not_ignored_by_default(self):
        """File is not ignored when there's no ignore-file comment."""
        source = """def normal_code():
    pass
"""
        handler = IgnoreHandler()
        handler.parse(source)

        assert handler.is_file_ignored() is False


class TestIgnoreRequiresReason:
    """Tests that ignores without reason are NOT parsed."""

    def test_same_line_ignore_without_reason_not_parsed(self):
        """Same-line ignore without reason is not parsed."""
        source = 'password = "secret"  # hackmenot:ignore[SEC001]'
        handler = IgnoreHandler()
        ignores = handler.parse(source)

        assert len(ignores) == 0

    def test_next_line_ignore_without_reason_not_parsed(self):
        """Next-line ignore without reason is not parsed."""
        source = """# hackmenot:ignore-next-line[SEC001]
password = "secret"
"""
        handler = IgnoreHandler()
        ignores = handler.parse(source)

        assert len(ignores) == 0

    def test_file_ignore_without_reason_not_parsed(self):
        """File-level ignore without reason is not parsed."""
        source = """# hackmenot:ignore-file
def code():
    pass
"""
        handler = IgnoreHandler()
        handler.parse(source)

        assert handler.is_file_ignored() is False

    def test_empty_reason_not_valid(self):
        """Empty reason (just dash) is not valid."""
        source = 'x = 1  # hackmenot:ignore[SEC001] - '
        handler = IgnoreHandler()
        ignores = handler.parse(source)

        assert len(ignores) == 0


class TestShouldIgnore:
    """Tests for the should_ignore helper method."""

    def test_should_ignore_returns_true_for_ignored_line(self):
        """should_ignore returns True for line/rule in ignore set."""
        source = 'password = "secret"  # hackmenot:ignore[SEC001] - test'
        handler = IgnoreHandler()
        handler.parse(source)

        assert handler.should_ignore(1, "SEC001") is True

    def test_should_ignore_returns_false_for_different_line(self):
        """should_ignore returns False for different line number."""
        source = 'password = "secret"  # hackmenot:ignore[SEC001] - test'
        handler = IgnoreHandler()
        handler.parse(source)

        assert handler.should_ignore(2, "SEC001") is False

    def test_should_ignore_returns_false_for_different_rule(self):
        """should_ignore returns False for different rule ID."""
        source = 'password = "secret"  # hackmenot:ignore[SEC001] - test'
        handler = IgnoreHandler()
        handler.parse(source)

        assert handler.should_ignore(1, "AUTH002") is False

    def test_should_ignore_returns_true_when_file_ignored(self):
        """should_ignore returns True for any line/rule when file is ignored."""
        source = """# hackmenot:ignore-file - test file
def code():
    pass
"""
        handler = IgnoreHandler()
        handler.parse(source)

        assert handler.should_ignore(1, "ANY001") is True
        assert handler.should_ignore(2, "OTHER002") is True
        assert handler.should_ignore(100, "RULE003") is True

    def test_should_ignore_with_next_line(self):
        """should_ignore works with next-line ignores."""
        source = """# hackmenot:ignore-next-line[SEC001] - reason
password = "secret"
other_line
"""
        handler = IgnoreHandler()
        handler.parse(source)

        assert handler.should_ignore(2, "SEC001") is True
        assert handler.should_ignore(1, "SEC001") is False
        assert handler.should_ignore(3, "SEC001") is False


class TestIsFileIgnored:
    """Tests for is_file_ignored method."""

    def test_is_file_ignored_with_source_param(self):
        """is_file_ignored can accept source as parameter."""
        source = "# hackmenot:ignore-file - test file"
        handler = IgnoreHandler()

        # Should parse and check in one call
        assert handler.is_file_ignored(source) is True

    def test_is_file_ignored_without_parse(self):
        """is_file_ignored returns False if parse not called and no source given."""
        handler = IgnoreHandler()
        assert handler.is_file_ignored() is False
