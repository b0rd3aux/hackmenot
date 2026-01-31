"""Tests for scanner config integration."""

from pathlib import Path

from hackmenot.core.config import Config
from hackmenot.core.scanner import Scanner


def test_scanner_respects_disabled_rules(tmp_path: Path):
    """Test scanner skips disabled rules."""
    config = Config(rules_disable=["INJ001"])
    scanner = Scanner(config=config)
    (tmp_path / "test.py").write_text('query = f"SELECT * FROM users WHERE id = {x}"')
    result = scanner.scan([tmp_path])
    assert not any(f.rule_id == "INJ001" for f in result.findings)


def test_scanner_respects_path_excludes(tmp_path: Path):
    """Test scanner excludes paths matching exclude patterns."""
    config = Config(paths_exclude=["tests/*"])
    scanner = Scanner(config=config)
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test.py").write_text('query = f"SELECT * FROM x WHERE y = {z}"')
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1")
    result = scanner.scan([tmp_path])
    assert result.files_scanned == 1


def test_scanner_uses_default_config_when_none_provided(tmp_path: Path):
    """Test scanner works with default config."""
    scanner = Scanner()
    assert scanner.config is not None
    assert scanner.config.rules_disable == []
    assert scanner.config.paths_exclude == []


def test_scanner_excludes_multiple_path_patterns(tmp_path: Path):
    """Test scanner excludes multiple path patterns."""
    config = Config(paths_exclude=["tests/*", "vendor/*"])
    scanner = Scanner(config=config)

    # Create excluded directories
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test.py").write_text('query = f"SELECT * FROM x WHERE y = {z}"')
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.py").write_text('query = f"SELECT * FROM a WHERE b = {c}"')

    # Create included directory
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1")

    result = scanner.scan([tmp_path])
    assert result.files_scanned == 1


def test_scanner_disables_multiple_rules(tmp_path: Path):
    """Test scanner can disable multiple rules."""
    config = Config(rules_disable=["INJ001", "INJ002"])
    scanner = Scanner(config=config)
    (tmp_path / "test.py").write_text('query = f"SELECT * FROM users WHERE id = {x}"')
    result = scanner.scan([tmp_path])
    # Neither INJ001 nor INJ002 should be in findings
    assert not any(f.rule_id in ("INJ001", "INJ002") for f in result.findings)
