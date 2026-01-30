"""Rules engine for matching patterns against parsed code."""

from pathlib import Path

from hackmenot.core.models import Finding, Rule
from hackmenot.parsers.base import ParseResult


class RulesEngine:
    """Engine for checking code against security rules."""

    def __init__(self) -> None:
        self.rules: dict[str, Rule] = {}

    def register_rule(self, rule: Rule) -> None:
        """Register a rule with the engine."""
        self.rules[rule.id] = rule

    def check(self, parse_result: ParseResult, file_path: Path) -> list[Finding]:
        """Check parsed code against all registered rules."""
        if parse_result.has_error:
            return []

        findings: list[Finding] = []
        language = self._detect_language(file_path)

        for rule in self.rules.values():
            if language not in rule.languages:
                continue

            rule_findings = self._check_rule(rule, parse_result, file_path)
            findings.extend(rule_findings)

        return findings

    def _detect_language(self, file_path: Path) -> str:
        """Detect language from file extension."""
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
        }
        return ext_map.get(file_path.suffix.lower(), "unknown")

    def _check_rule(self, rule: Rule, parse_result: ParseResult, file_path: Path) -> list[Finding]:
        """Check a single rule against parsed code."""
        findings: list[Finding] = []
        pattern = rule.pattern
        pattern_type = pattern.get("type", "")

        if pattern_type == "fstring":
            findings.extend(self._check_fstring_pattern(rule, parse_result, file_path))
        elif pattern_type == "function":
            findings.extend(self._check_function_pattern(rule, parse_result, file_path))

        return findings

    def _check_fstring_pattern(
        self, rule: Rule, parse_result: ParseResult, file_path: Path
    ) -> list[Finding]:
        """Check f-string patterns."""
        findings: list[Finding] = []
        contains = rule.pattern.get("contains", [])

        for fstring in parse_result.get_fstrings():
            # Check if f-string contains any of the target strings
            if any(kw.upper() in fstring.value.upper() for kw in contains):
                # Only flag if there are interpolated variables
                if fstring.variables:
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            message=rule.message,
                            file_path=str(file_path),
                            line_number=fstring.line_number,
                            column=fstring.column,
                            code_snippet=f'f"{fstring.value}"',
                            fix_suggestion=rule.fix_template,
                            education=rule.education,
                        )
                    )

        return findings

    def _check_function_pattern(
        self, rule: Rule, parse_result: ParseResult, file_path: Path
    ) -> list[Finding]:
        """Check function patterns (decorators, etc.)."""
        findings: list[Finding] = []

        has_decorator = rule.pattern.get("has_decorator", [])
        missing_decorator = rule.pattern.get("missing_decorator", [])

        for func in parse_result.get_functions():
            # Check if function has required decorator
            has_target = any(any(d in dec for d in has_decorator) for dec in func.decorators)

            if has_target:
                # Check if missing security decorator
                has_security = any(
                    any(s in dec for s in missing_decorator) for dec in func.decorators
                )

                if not has_security:
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            message=rule.message.format(function_name=func.name),
                            file_path=str(file_path),
                            line_number=func.line_number,
                            column=func.column,
                            code_snippet=f"def {func.name}(...):",
                            fix_suggestion=rule.fix_template,
                            education=rule.education,
                        )
                    )

        return findings
