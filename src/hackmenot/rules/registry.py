"""Rule registry for loading and managing rules."""

from collections.abc import Iterator
from pathlib import Path

import yaml

from hackmenot.core.models import FixConfig, Rule, Severity


class RuleRegistry:
    """Registry for loading rules from YAML files."""

    def __init__(self, rules_dir: Path | None = None) -> None:
        self.rules_dir = rules_dir or self._default_rules_dir()
        self._rules: dict[str, Rule] = {}

    def _default_rules_dir(self) -> Path:
        """Get default rules directory."""
        return Path(__file__).parent / "builtin"

    def load_all(self) -> None:
        """Load all rules from the rules directory."""
        if not self.rules_dir.exists():
            return

        for rule_file in self.rules_dir.rglob("*.yml"):
            self._load_rule_file(rule_file)

        for rule_file in self.rules_dir.rglob("*.yaml"):
            self._load_rule_file(rule_file)

    def _load_rule_file(self, file_path: Path) -> None:
        """Load a single rule file."""
        try:
            with open(file_path) as f:
                data = yaml.safe_load(f)

            if data:
                rule = self._parse_rule(data)
                self._rules[rule.id] = rule
        except Exception as e:
            # Log error but continue loading other rules
            print(f"Warning: Failed to load rule {file_path}: {e}")

    def _parse_rule(self, data: dict) -> Rule:
        """Parse rule data into Rule object.

        Supports both old and new YAML formats:
        - Old: fix_template: "Use parameterized queries"
        - New: fix:
                 template: "Use parameterized queries"
                 pattern: 'db.Query("{sql}" + {var})'
                 replacement: 'db.Query("{sql}", {var})'
        """
        # Handle fix configuration (backward compatible)
        fix_data = data.get("fix")
        fix_template = data.get("fix_template", "")

        if isinstance(fix_data, dict):
            # New format: fix is a dict with template, pattern, replacement
            fix = FixConfig(
                template=fix_data.get("template", ""),
                pattern=fix_data.get("pattern", ""),
                replacement=fix_data.get("replacement", ""),
            )
        elif fix_template:
            # Old format: fix_template is a string
            fix = FixConfig(template=fix_template)
        else:
            # No fix specified
            fix = FixConfig()

        return Rule(
            id=data["id"],
            name=data["name"],
            severity=Severity.from_string(data["severity"]),
            category=data["category"],
            languages=data.get("languages", ["python"]),
            description=data.get("description", ""),
            message=data["message"],
            pattern=data.get("pattern", {}),
            fix=fix,
            education=data.get("education", ""),
            references=data.get("references", []),
        )

    def get_rule(self, rule_id: str) -> Rule | None:
        """Get a rule by ID."""
        return self._rules.get(rule_id)

    def get_all_rules(self) -> Iterator[Rule]:
        """Iterate over all loaded rules."""
        yield from self._rules.values()

    def get_rules_by_category(self, category: str) -> Iterator[Rule]:
        """Get all rules in a category."""
        for rule in self._rules.values():
            if rule.category == category:
                yield rule
