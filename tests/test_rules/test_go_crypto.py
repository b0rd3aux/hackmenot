"""Tests for Go crypto rules."""

from pathlib import Path

import pytest

from hackmenot.core.scanner import Scanner


class TestGoCryptoRules:
    """Tests for Go crypto rule detection."""

    @pytest.fixture
    def scanner(self):
        return Scanner()

    def test_weak_hash_md5_detected(self, scanner, tmp_path):
        """Test GO_CRY001 detects MD5 usage."""
        go_file = tmp_path / "main.go"
        go_file.write_text('''
package main

import "crypto/md5"

func hash(data []byte) []byte {
    h := md5.Sum(data)
    return h[:]
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "GO_CRY001"]
        assert len(findings) >= 1

    def test_weak_hash_sha1_detected(self, scanner, tmp_path):
        """Test GO_CRY002 detects SHA1 usage."""
        go_file = tmp_path / "main.go"
        go_file.write_text('''
package main

import "crypto/sha1"

func hash(data []byte) []byte {
    h := sha1.Sum(data)
    return h[:]
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "GO_CRY002"]
        assert len(findings) >= 1

    def test_insecure_tls_detected(self, scanner, tmp_path):
        """Test GO_CRY003 detects InsecureSkipVerify."""
        go_file = tmp_path / "main.go"
        go_file.write_text('''
package main

import (
    "crypto/tls"
    "net/http"
)

func createClient() *http.Client {
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    return &http.Client{Transport: tr}
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "GO_CRY003"]
        assert len(findings) >= 1

    def test_weak_random_detected(self, scanner, tmp_path):
        """Test GO_CRY004 detects math/rand usage."""
        go_file = tmp_path / "main.go"
        go_file.write_text('''
package main

import "math/rand"

func generateToken() int {
    return rand.Int()
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "GO_CRY004"]
        assert len(findings) >= 1

    def test_hardcoded_iv_detected(self, scanner, tmp_path):
        """Test GO_CRY005 detects hardcoded IV."""
        go_file = tmp_path / "main.go"
        go_file.write_text('''
package main

func encrypt(data []byte) []byte {
    iv := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
    nonce := "hardcoded_nonce_value"
    return data
}
''')
        result = scanner.scan([tmp_path])
        findings = [f for f in result.findings if f.rule_id == "GO_CRY005"]
        assert len(findings) >= 1

    def test_clean_crypto_code_no_findings(self, scanner, tmp_path):
        """Test that secure Go crypto code has no crypto findings."""
        go_file = tmp_path / "main.go"
        go_file.write_text('''
package main

import (
    "crypto/rand"
    "crypto/sha256"
)

func secureHash(data []byte) [32]byte {
    return sha256.Sum256(data)
}

func secureRandom() []byte {
    bytes := make([]byte, 32)
    rand.Read(bytes)
    return bytes
}
''')
        result = scanner.scan([tmp_path])
        crypto_findings = [f for f in result.findings if f.rule_id.startswith("GO_CRY")]
        assert len(crypto_findings) == 0
