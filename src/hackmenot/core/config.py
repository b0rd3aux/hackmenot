"""Configuration loading for hackmenot."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class Config:
    """Configuration for hackmenot scanner."""

    fail_on: str = "high"
    rules_disable: list[str] = field(default_factory=list)
    rules_enable: list[str] = field(default_factory=lambda: ["all"])
    severity_override: dict[str, str] = field(default_factory=dict)
    paths_include: list[str] = field(default_factory=list)
    paths_exclude: list[str] = field(default_factory=list)
    fixes_auto_apply_safe: bool = True


class ConfigLoader:
    """Loads configuration from .hackmenot.yml files."""

    CONFIG_FILENAMES = [".hackmenot.yml", ".hackmenot.yaml"]

    def __init__(self, global_config_dir: Path | None = None) -> None:
        """Initialize ConfigLoader.

        Args:
            global_config_dir: Directory containing global config.
                              Defaults to ~/.config/hackmenot
        """
        self.global_config_dir = global_config_dir or Path.home() / ".config" / "hackmenot"

    def load(self, project_dir: Path) -> Config:
        """Load configuration, merging global and project configs.

        Project config values override global config values.

        Args:
            project_dir: Project directory to load config from.

        Returns:
            Merged configuration.
        """
        # Start with defaults
        merged: dict[str, Any] = {}

        # Load global config if it exists
        global_config = self._load_from_dir(self.global_config_dir)
        if global_config:
            merged = self._merge_config(merged, global_config)

        # Load project config and override global
        project_config = self._load_from_dir(project_dir)
        if project_config:
            merged = self._merge_config(merged, project_config)

        return self._dict_to_config(merged)

    def load_from_file(self, config_path: Path) -> Config:
        """Load configuration from a specific file path.

        Args:
            config_path: Path to the config file.

        Returns:
            Config loaded from the file.

        Raises:
            FileNotFoundError: If the config file does not exist.
        """
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        data = self._parse_yaml(config_path)
        return self._dict_to_config(data)

    def _load_from_dir(self, directory: Path) -> dict[str, Any] | None:
        """Load config from a directory.

        Args:
            directory: Directory to search for config file.

        Returns:
            Parsed config dict or None if no config found.
        """
        for filename in self.CONFIG_FILENAMES:
            config_path = directory / filename
            if config_path.exists():
                return self._parse_yaml(config_path)
        return None

    def _parse_yaml(self, path: Path) -> dict[str, Any]:
        """Parse a YAML config file.

        Args:
            path: Path to YAML file.

        Returns:
            Parsed config dict.
        """
        with open(path, encoding="utf-8") as f:
            content = yaml.safe_load(f)
            return content if content else {}

    def _merge_config(
        self, base: dict[str, Any], override: dict[str, Any]
    ) -> dict[str, Any]:
        """Merge override config into base config.

        Override values replace base values (no deep merge).

        Args:
            base: Base configuration.
            override: Configuration to merge on top.

        Returns:
            Merged configuration.
        """
        result = base.copy()

        for key, value in override.items():
            if isinstance(value, dict) and key in result and isinstance(result[key], dict):
                # Shallow merge for nested dicts
                result[key] = {**result[key], **value}
            else:
                result[key] = value

        return result

    def _dict_to_config(self, data: dict[str, Any]) -> Config:
        """Convert a config dict to Config dataclass.

        Args:
            data: Raw config dict from YAML.

        Returns:
            Config instance.
        """
        rules = data.get("rules", {})
        paths = data.get("paths", {})
        fixes = data.get("fixes", {})

        return Config(
            fail_on=data.get("fail_on", "high"),
            rules_disable=rules.get("disable", []),
            rules_enable=rules.get("enable", ["all"]),
            severity_override=data.get("severity_override", {}),
            paths_include=paths.get("include", []),
            paths_exclude=paths.get("exclude", []),
            fixes_auto_apply_safe=fixes.get("auto_apply_safe", True),
        )
