"""Tests for Go unsafe and network rules."""

from pathlib import Path

import pytest

from hackmenot.core.scanner import Scanner


class TestGoUnsafeNetworkRules:
    """Tests for Go unsafe and network rule detection."""

    @pytest.fixture
    def scanner(self):
        return Scanner()

    def test_unsafe_pointer_detected(self, scanner, tmp_path):
        """Test GO_UNS001 detects unsafe package import."""
        go_file = tmp_path / "main.go"
        go_file.write_text('''
package main

import "unsafe"

func dangerousPointer() {
    var x int = 42
    ptr := unsafe.Pointer(&x)
    _ = ptr
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "GO_UNS001"]
        assert len(findings) >= 1

    def test_cgo_usage_detected(self, scanner, tmp_path):
        """Test GO_UNS002 detects CGO import pattern in code."""
        go_file = tmp_path / "main.go"
        # Use raw string literal (backticks) to contain the CGO import pattern
        go_file.write_text('''
package main

func checkCGO() string {
    // Code that references CGO pattern
    pattern := `import "C"`
    return pattern
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "GO_UNS002"]
        assert len(findings) >= 1

    def test_ssrf_detected(self, scanner, tmp_path):
        """Test GO_NET001 detects potential SSRF."""
        go_file = tmp_path / "main.go"
        go_file.write_text('''
package main

import "net/http"

func fetchURL(userURL string) {
    http.Get(userURL)
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "GO_NET001"]
        assert len(findings) >= 1

    def test_open_redirect_detected(self, scanner, tmp_path):
        """Test GO_NET002 detects potential open redirect."""
        go_file = tmp_path / "main.go"
        go_file.write_text('''
package main

import "net/http"

func redirectHandler(w http.ResponseWriter, r *http.Request) {
    targetURL := r.URL.Query().Get("url")
    http.Redirect(w, r, targetURL, http.StatusFound)
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "GO_NET002"]
        assert len(findings) >= 1

    def test_unvalidated_url_detected(self, scanner, tmp_path):
        """Test GO_NET003 detects unvalidated URL parsing."""
        go_file = tmp_path / "main.go"
        go_file.write_text('''
package main

import "net/url"

func parseUserURL(userInput string) {
    url.Parse(userInput)
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "GO_NET003"]
        assert len(findings) >= 1

    def test_clean_code_no_unsafe_network_findings(self, scanner, tmp_path):
        """Test that clean Go code has no unsafe/network findings."""
        go_file = tmp_path / "main.go"
        go_file.write_text('''
package main

import "fmt"

func main() {
    fmt.Println("Safe and sound!")
}
''')
        result = scanner.scan([tmp_path])
        unsafe_net_findings = [
            f for f in result.findings
            if f.rule_id.startswith("GO_UNS") or f.rule_id.startswith("GO_NET")
        ]
        assert len(unsafe_net_findings) == 0
