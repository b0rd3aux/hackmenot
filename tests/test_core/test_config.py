"""Tests for configuration loading."""

from pathlib import Path

import pytest
import yaml

from hackmenot.core.config import Config, ConfigLoader


def test_config_defaults():
    """Verify default Config values."""
    config = Config()

    assert config.fail_on == "high"
    assert config.rules_disable == []
    assert config.rules_enable == ["all"]
    assert config.severity_override == {}
    assert config.paths_include == []
    assert config.paths_exclude == []
    assert config.fixes_auto_apply_safe is True


def test_load_config_from_file(tmp_path: Path):
    """Load .hackmenot.yml and verify values."""
    config_content = {
        "fail_on": "critical",
        "rules": {
            "disable": ["AUTH001", "INJ002"],
            "enable": ["AUTH001", "INJ001"],
        },
        "severity_override": {
            "AUTH001": "critical",
        },
        "paths": {
            "include": ["src/"],
            "exclude": ["tests/", "vendor/"],
        },
        "fixes": {
            "auto_apply_safe": False,
        },
    }

    config_file = tmp_path / ".hackmenot.yml"
    config_file.write_text(yaml.dump(config_content))

    loader = ConfigLoader()
    config = loader.load(tmp_path)

    assert config.fail_on == "critical"
    assert config.rules_disable == ["AUTH001", "INJ002"]
    assert config.rules_enable == ["AUTH001", "INJ001"]
    assert config.severity_override == {"AUTH001": "critical"}
    assert config.paths_include == ["src/"]
    assert config.paths_exclude == ["tests/", "vendor/"]
    assert config.fixes_auto_apply_safe is False


def test_load_config_missing_file(tmp_path: Path):
    """Verify defaults when no config file exists."""
    loader = ConfigLoader()
    config = loader.load(tmp_path)

    # Should return defaults when file doesn't exist
    assert config.fail_on == "high"
    assert config.rules_disable == []
    assert config.rules_enable == ["all"]
    assert config.severity_override == {}
    assert config.paths_include == []
    assert config.paths_exclude == []
    assert config.fixes_auto_apply_safe is True


def test_config_merge_with_global(tmp_path: Path):
    """Project config overrides global config."""
    # Create global config directory
    global_config_dir = tmp_path / "global"
    global_config_dir.mkdir()

    global_config = {
        "fail_on": "medium",
        "rules": {
            "disable": ["AUTH001"],
            "enable": ["INJ001"],
        },
        "paths": {
            "exclude": ["vendor/"],
        },
    }
    global_config_file = global_config_dir / ".hackmenot.yml"
    global_config_file.write_text(yaml.dump(global_config))

    # Create project config directory
    project_dir = tmp_path / "project"
    project_dir.mkdir()

    project_config = {
        "fail_on": "high",
        "rules": {
            "disable": ["INJ002"],  # Should override, not extend
        },
    }
    project_config_file = project_dir / ".hackmenot.yml"
    project_config_file.write_text(yaml.dump(project_config))

    loader = ConfigLoader(global_config_dir=global_config_dir)
    config = loader.load(project_dir)

    # Project values should override global
    assert config.fail_on == "high"
    assert config.rules_disable == ["INJ002"]
    # Values not in project should come from global
    assert config.rules_enable == ["INJ001"]
    assert config.paths_exclude == ["vendor/"]


def test_load_config_partial_file(tmp_path: Path):
    """Config file with only some fields uses defaults for the rest."""
    config_content = {
        "fail_on": "low",
    }

    config_file = tmp_path / ".hackmenot.yml"
    config_file.write_text(yaml.dump(config_content))

    loader = ConfigLoader()
    config = loader.load(tmp_path)

    assert config.fail_on == "low"
    # Other fields should be defaults
    assert config.rules_disable == []
    assert config.rules_enable == ["all"]
    assert config.fixes_auto_apply_safe is True


def test_load_config_yaml_extension(tmp_path: Path):
    """Config file with .yaml extension also works."""
    config_content = {
        "fail_on": "critical",
    }

    config_file = tmp_path / ".hackmenot.yaml"
    config_file.write_text(yaml.dump(config_content))

    loader = ConfigLoader()
    config = loader.load(tmp_path)

    assert config.fail_on == "critical"


def test_load_config_prefers_yml_over_yaml(tmp_path: Path):
    """When both .yml and .yaml exist, prefer .yml."""
    yml_content = {"fail_on": "high"}
    yaml_content = {"fail_on": "low"}

    yml_file = tmp_path / ".hackmenot.yml"
    yml_file.write_text(yaml.dump(yml_content))

    yaml_file = tmp_path / ".hackmenot.yaml"
    yaml_file.write_text(yaml.dump(yaml_content))

    loader = ConfigLoader()
    config = loader.load(tmp_path)

    assert config.fail_on == "high"
