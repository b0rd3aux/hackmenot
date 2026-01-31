"""Fix engine for applying template-based code fixes."""

from hackmenot.core.models import Finding


class FixEngine:
    """Engine for applying fix suggestions to source code."""

    def apply_fix(self, source: str, finding: Finding) -> str | None:
        """Apply a single fix to source code.

        Args:
            source: The original source code.
            finding: The finding containing the fix_suggestion.

        Returns:
            The modified source code, or None if no fix_suggestion.
        """
        # Return None if no fix_suggestion
        if not finding.fix_suggestion:
            return None

        lines = source.split("\n")
        line_idx = finding.line_number - 1

        # Get indentation from original line
        original_line = lines[line_idx]
        indent = len(original_line) - len(original_line.lstrip())
        indent_str = original_line[:indent]

        # Apply fix with proper indentation
        fix_lines = [
            indent_str + line.lstrip() if line.strip() else line
            for line in finding.fix_suggestion.split("\n")
        ]

        lines[line_idx : line_idx + 1] = fix_lines
        return "\n".join(lines)

    def apply_fixes(
        self, source: str, findings: list[Finding]
    ) -> tuple[str, int]:
        """Apply multiple fixes to source code.

        Fixes are applied from bottom to top to preserve line numbers.

        Args:
            source: The original source code.
            findings: List of findings containing fix suggestions.

        Returns:
            Tuple of (modified source code, number of fixes applied).
        """
        # Sort findings by line number descending (bottom to top)
        sorted_findings = sorted(
            findings, key=lambda f: f.line_number, reverse=True
        )

        applied_count = 0
        result = source

        for finding in sorted_findings:
            fixed = self.apply_fix(result, finding)
            if fixed is not None:
                result = fixed
                applied_count += 1

        return result, applied_count
