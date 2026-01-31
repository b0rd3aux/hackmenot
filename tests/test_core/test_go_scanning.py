"""Tests for Go file scanning integration."""

from pathlib import Path
import pytest
from hackmenot.core.scanner import Scanner


class TestGoScanning:
    """Tests for scanning Go files."""

    def test_scanner_detects_go_files(self, tmp_path):
        """Test that scanner recognizes .go files."""
        go_file = tmp_path / "main.go"
        go_file.write_text('package main\n\nfunc main() {}')
        scanner = Scanner()
        result = scanner.scan([tmp_path])
        assert result.files_scanned >= 1

    def test_scanner_supported_extensions_includes_go(self):
        """Test that .go is in supported extensions."""
        scanner = Scanner()
        assert ".go" in scanner.SUPPORTED_EXTENSIONS

    def test_scanner_detects_language_go(self, tmp_path):
        """Test language detection for Go files."""
        go_file = tmp_path / "main.go"
        go_file.write_text('package main')
        scanner = Scanner()
        lang = scanner._detect_language(go_file)
        assert lang == "go"
