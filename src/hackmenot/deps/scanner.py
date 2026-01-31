"""Main dependency scanner."""

import time
from pathlib import Path

from hackmenot.core.models import ScanResult
from hackmenot.deps.hallucination import HallucinationDetector
from hackmenot.deps.parser import DependencyParser
from hackmenot.deps.typosquat import TyposquatDetector
from hackmenot.deps.vulns import OSVClient


class DependencyScanner:
    """Scanner for dependency security issues."""

    def __init__(self) -> None:
        self.parser = DependencyParser()
        self.hallucination_detector = HallucinationDetector()
        self.typosquat_detector = TyposquatDetector()
        self.osv_client = OSVClient()

    def scan(self, directory: Path, check_vulns: bool = False) -> ScanResult:
        """Scan dependencies in a directory."""
        start_time = time.time()
        findings = []

        deps = self.parser.parse_directory(directory)
        files_scanned = len(set(d.source_file for d in deps))

        for dep in deps:
            # Hallucination check
            finding = self.hallucination_detector.check(dep)
            if finding:
                findings.append(finding)
                continue  # Skip typosquat if hallucinated

            # Typosquat check
            finding = self.typosquat_detector.check(dep)
            if finding:
                findings.append(finding)

        # Vulnerability check (optional)
        if check_vulns and deps:
            vuln_findings = self.osv_client.check_batch(deps)
            findings.extend(vuln_findings)

        scan_time_ms = (time.time() - start_time) * 1000
        return ScanResult(files_scanned=files_scanned, findings=findings, scan_time_ms=scan_time_ms)
