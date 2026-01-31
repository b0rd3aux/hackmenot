"""Pattern parser for smart fix matching."""

import re
from dataclasses import dataclass


# Placeholder definitions: name -> (regex pattern, description)
PLACEHOLDERS = {
    "var": (r"(\w+)", "variable name"),
    "func": (r"(\w+(?:\.\w+)*)", "function/method name"),
    "arg": (r"(.+?)", "function argument"),
    "args": (r"(.*?)", "multiple arguments"),
    "string": (r'(["\'].*?["\'])', "string literal"),
    "expr": (r"(.+)", "any expression"),
    "num": (r"(\d+)", "number"),
}


@dataclass
class ParsedPattern:
    """Result of parsing a fix pattern."""
    regex: re.Pattern
    placeholders: list[str]  # Names in order of capture groups
    original: str


class PatternParser:
    """Converts placeholder patterns to regex and applies replacements."""

    def parse(self, pattern: str) -> ParsedPattern:
        """Convert a pattern with placeholders to regex.

        Example:
            '{func}({arg})' -> regex with capture groups
        """
        placeholders = []
        regex_parts = []
        last_end = 0

        # Find all {placeholder} in pattern
        for match in re.finditer(r'\{(\w+)\}', pattern):
            # Add literal text before this placeholder
            literal = pattern[last_end:match.start()]
            regex_parts.append(re.escape(literal))

            # Get placeholder name and convert to regex
            name = match.group(1)
            if name in PLACEHOLDERS:
                regex_parts.append(PLACEHOLDERS[name][0])
                placeholders.append(name)
            else:
                # Unknown placeholder - treat as literal
                regex_parts.append(re.escape(match.group(0)))

            last_end = match.end()

        # Add remaining literal text
        regex_parts.append(re.escape(pattern[last_end:]))

        regex_str = "".join(regex_parts)
        return ParsedPattern(
            regex=re.compile(regex_str),
            placeholders=placeholders,
            original=pattern,
        )

    def apply_replacement(
        self,
        source: str,
        parsed: ParsedPattern,
        replacement: str
    ) -> str | None:
        """Apply replacement pattern using captured groups.

        Returns None if pattern doesn't match.
        """
        match = parsed.regex.search(source)
        if not match:
            return None

        # Build replacement string with captured values
        result = replacement
        for i, name in enumerate(parsed.placeholders, 1):
            result = result.replace(f"{{{name}}}", match.group(i))

        # Replace matched portion in source
        return source[:match.start()] + result + source[match.end():]
