"""Handler for inline ignore comments in source code."""

import re


class IgnoreHandler:
    """Parses and manages inline ignore comments for hackmenot.

    Supports three types of ignore comments:
    - Same-line: # hackmenot:ignore[RULE] - reason (or // for JavaScript)
    - Next-line: # hackmenot:ignore-next-line[RULE] - reason (or // for JavaScript)
    - File-level: # hackmenot:ignore-file - reason (or // for JavaScript)

    All ignore comments require a reason (after the dash) to be valid.
    Supports both Python-style (#) and JavaScript-style (//) comments.
    """

    # Pattern for same-line ignores: # hackmenot:ignore[RULE] - reason
    # Matches at end of line, requires non-empty reason after dash
    # Supports both # and // comment styles
    SAME_LINE_PATTERN = re.compile(
        r"(?:#|//)\s*hackmenot:ignore\[([A-Z]+\d+)\]\s*-\s*(.+)$"
    )

    # Pattern for next-line ignores: # hackmenot:ignore-next-line[RULE] - reason
    # Matches as a standalone comment line (possibly indented)
    # Supports both # and // comment styles
    NEXT_LINE_PATTERN = re.compile(
        r"^\s*(?:#|//)\s*hackmenot:ignore-next-line\[([A-Z]+\d+)\]\s*-\s*(.+)$"
    )

    # Pattern for file-level ignores: # hackmenot:ignore-file - reason
    # Matches as a standalone comment line (possibly indented)
    # Supports both # and // comment styles
    FILE_IGNORE_PATTERN = re.compile(
        r"^\s*(?:#|//)\s*hackmenot:ignore-file\s*-\s*(.+)$"
    )

    def __init__(self) -> None:
        """Initialize the IgnoreHandler."""
        self._ignores: set[tuple[int, str]] = set()
        self._file_ignored: bool = False

    def parse(self, source: str) -> set[tuple[int, str]]:
        """Parse source for ignore comments.

        Args:
            source: The source code to parse for ignore comments.

        Returns:
            Set of (line_number, rule_id) tuples indicating which lines/rules
            should be ignored. Line numbers are 1-indexed.
        """
        self._ignores = set()
        self._file_ignored = False

        lines = source.splitlines()

        for line_num, line in enumerate(lines, start=1):
            # Check for file-level ignore
            file_match = self.FILE_IGNORE_PATTERN.match(line)
            if file_match:
                reason = file_match.group(1).strip()
                if reason:  # Ensure reason is not empty
                    self._file_ignored = True
                continue

            # Check for next-line ignore
            next_line_match = self.NEXT_LINE_PATTERN.match(line)
            if next_line_match:
                rule_id = next_line_match.group(1)
                reason = next_line_match.group(2).strip()
                if reason:  # Ensure reason is not empty
                    # Apply to the next line
                    self._ignores.add((line_num + 1, rule_id))
                continue

            # Check for same-line ignore
            same_line_match = self.SAME_LINE_PATTERN.search(line)
            if same_line_match:
                rule_id = same_line_match.group(1)
                reason = same_line_match.group(2).strip()
                if reason:  # Ensure reason is not empty
                    self._ignores.add((line_num, rule_id))

        return self._ignores

    def is_file_ignored(self, source: str | None = None) -> bool:
        """Check if the entire file is ignored.

        Args:
            source: Optional source code to parse. If provided, parse() will
                    be called before checking the file ignored status.

        Returns:
            True if the file has a valid ignore-file comment, False otherwise.
        """
        if source is not None:
            self.parse(source)
        return self._file_ignored

    def should_ignore(self, line_number: int, rule_id: str) -> bool:
        """Check if a specific line/rule combination should be ignored.

        Args:
            line_number: The 1-indexed line number to check.
            rule_id: The rule ID to check (e.g., "SEC001").

        Returns:
            True if the line/rule should be ignored, False otherwise.
            Always returns True for any line/rule if the file is ignored.
        """
        if self._file_ignored:
            return True
        return (line_number, rule_id) in self._ignores
