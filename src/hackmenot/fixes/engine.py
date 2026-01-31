"""Fix engine for applying template-based code fixes."""

from dataclasses import dataclass

from hackmenot.core.models import Finding, Rule
from hackmenot.fixes.patterns import PatternParser


@dataclass
class FixResult:
    """Result of applying a fix."""

    applied: bool
    original: str = ""
    fixed: str = ""
    reason: str = ""  # "success", "no_match", "no_fix_defined", "pattern_error"


class FixEngine:
    """Engine for applying fix suggestions to source code."""

    def apply_fix(
        self, source: str, finding: Finding, rule: Rule | None = None
    ) -> FixResult:
        """Apply a fix to source code.

        Tries pattern-based fix first, falls back to template replacement.

        Args:
            source: The original source code.
            finding: The finding containing the fix_suggestion.
            rule: Optional rule with fix configuration.

        Returns:
            FixResult with details about the fix operation.
        """
        lines = source.split("\n")
        line_idx = finding.line_number - 1

        if line_idx < 0 or line_idx >= len(lines):
            return FixResult(applied=False, reason="invalid_line")

        original_line = lines[line_idx]

        # Try pattern-based fix first (if rule provided)
        if rule and rule.fix.pattern and rule.fix.replacement:
            parser = PatternParser()
            try:
                parsed = parser.parse(rule.fix.pattern)
                fixed_line = parser.apply_replacement(
                    original_line, parsed, rule.fix.replacement
                )
                if fixed_line is not None:
                    lines[line_idx] = fixed_line
                    return FixResult(
                        applied=True,
                        original=original_line,
                        fixed=fixed_line,
                        reason="success",
                    )
            except Exception:
                pass  # Fall through to template-based

        # Fall back to template-based fix (if rule provided)
        if rule and rule.fix.template:
            template = rule.fix.template.strip()
            indent = len(original_line) - len(original_line.lstrip())
            indent_str = " " * indent

            # Check if template is guidance-only (all lines are comments)
            template_lines = template.split("\n")
            is_guidance_only = all(
                line.strip().startswith("#") or line.strip().startswith("//") or not line.strip()
                for line in template_lines
            )

            if is_guidance_only:
                # Add guidance as comment above the line, keep original code
                guidance_lines = [indent_str + line.lstrip() for line in template_lines]
                fixed_content = "\n".join(guidance_lines) + "\n" + original_line
                lines[line_idx] = fixed_content
                return FixResult(
                    applied=True,
                    original=original_line,
                    fixed=fixed_content,
                    reason="success",
                )
            else:
                # Template is actual code replacement
                fixed_line = indent_str + template.lstrip()
                lines[line_idx] = fixed_line
                return FixResult(
                    applied=True,
                    original=original_line,
                    fixed=fixed_line,
                    reason="success",
                )

        # Fall back to finding.fix_suggestion (legacy behavior)
        if finding.fix_suggestion:
            suggestion = finding.fix_suggestion.strip()
            indent = len(original_line) - len(original_line.lstrip())
            indent_str = original_line[:indent]

            # Check if suggestion is guidance-only (all lines are comments)
            suggestion_lines = suggestion.split("\n")
            is_guidance_only = all(
                line.strip().startswith("#") or line.strip().startswith("//") or not line.strip()
                for line in suggestion_lines
            )

            if is_guidance_only:
                # Add guidance as comment above the line, keep original code
                guidance_lines = [
                    indent_str + line.lstrip() if line.strip() else line
                    for line in suggestion_lines
                ]
                fixed_content = "\n".join(guidance_lines) + "\n" + original_line
                lines[line_idx : line_idx + 1] = [fixed_content]
                return FixResult(
                    applied=True,
                    original=original_line,
                    fixed=fixed_content,
                    reason="success",
                )
            else:
                # Apply fix with proper indentation (replaces original)
                fix_lines = [
                    indent_str + line.lstrip() if line.strip() else line
                    for line in suggestion_lines
                ]
                lines[line_idx : line_idx + 1] = fix_lines
                return FixResult(
                    applied=True,
                    original=original_line,
                    fixed="\n".join(fix_lines),
                    reason="success",
                )

        return FixResult(applied=False, reason="no_fix_defined")

    def apply_fixes(
        self,
        source: str,
        findings: list[Finding],
        rules: dict[str, Rule] | None = None,
    ) -> tuple[str, int]:
        """Apply multiple fixes to source code.

        Fixes are applied from bottom to top to preserve line numbers.

        Args:
            source: The original source code.
            findings: List of findings containing fix suggestions.
            rules: Optional dict mapping rule_id to Rule for pattern-based fixes.

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
            rule = rules.get(finding.rule_id) if rules else None
            fix_result = self.apply_fix(result, finding, rule)
            if fix_result.applied:
                # Rebuild source with the fix applied
                lines = result.split("\n")
                line_idx = finding.line_number - 1
                if 0 <= line_idx < len(lines):
                    # Handle multi-line fixes
                    fixed_lines = fix_result.fixed.split("\n")
                    lines[line_idx : line_idx + 1] = fixed_lines
                    result = "\n".join(lines)
                    applied_count += 1

        return result, applied_count
