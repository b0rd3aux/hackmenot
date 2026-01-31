"""SARIF reporter for GitHub Code Scanning integration."""

import json

from hackmenot import __version__
from hackmenot.core.models import Finding, ScanResult, Severity
from hackmenot.reporters.base import BaseReporter


class SARIFReporter(BaseReporter):
    """SARIF 2.1.0 format reporter for GitHub Code Scanning."""

    SEVERITY_MAP = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
    }

    def render(self, result: ScanResult) -> str:
        """Render scan results as SARIF JSON."""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": self._tool_component(result),
                    "results": self._results(result.findings),
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    def _tool_component(self, result: ScanResult) -> dict:
        """Build the tool component with driver and rules."""
        return {
            "driver": {
                "name": "hackmenot",
                "version": __version__,
                "informationUri": "https://github.com/hackmenot/hackmenot",
                "rules": self._rules(result.findings),
            }
        }

    def _rules(self, findings: list[Finding]) -> list[dict]:
        """Build deduplicated rule definitions from findings."""
        seen_rules: dict[str, dict] = {}

        for finding in findings:
            if finding.rule_id not in seen_rules:
                seen_rules[finding.rule_id] = {
                    "id": finding.rule_id,
                    "name": finding.rule_name,
                    "shortDescription": {"text": finding.rule_name},
                    "defaultConfiguration": {
                        "level": self.SEVERITY_MAP[finding.severity]
                    },
                    "helpUri": f"https://hackmenot.dev/rules/{finding.rule_id}",
                }

        return list(seen_rules.values())

    def _results(self, findings: list[Finding]) -> list[dict]:
        """Build SARIF results from findings."""
        return [self._result(finding) for finding in findings]

    def _result(self, finding: Finding) -> dict:
        """Convert a single finding to SARIF result format."""
        return {
            "ruleId": finding.rule_id,
            "level": self.SEVERITY_MAP[finding.severity],
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file_path},
                        "region": {
                            "startLine": finding.line_number,
                            "startColumn": finding.column,
                        },
                    }
                }
            ],
        }
