"""Markdown reporter for PR comments."""

from hackmenot import __version__
from hackmenot.core.models import ScanResult, Severity
from hackmenot.reporters.base import BaseReporter


class MarkdownReporter(BaseReporter):
    """Generate markdown for PR comments."""

    SEVERITY_EMOJI = {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🟢",
    }

    def render(self, result: ScanResult) -> str:
        """Render scan results as markdown."""
        lines = []
        lines.append("## 🔒 hackmenot Security Scan\n")

        if not result.has_findings:
            lines.append("✅ **No security issues found!**\n")
        else:
            lines.append(f"**Found {len(result.findings)} issues** in {result.files_scanned} files scanned\n")
            lines.append(self._severity_table(result))
            lines.append("")
            lines.append(self._findings_list(result))

        lines.append("\n---")
        lines.append(f"*Scanned by [hackmenot](https://github.com/hackmenot/hackmenot) v{__version__}*")
        return "\n".join(lines)

    def _severity_table(self, result: ScanResult) -> str:
        """Build severity summary table."""
        summary = result.summary_by_severity()
        lines = ["| Severity | Count |", "|----------|-------|"]
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            emoji = self.SEVERITY_EMOJI[sev]
            lines.append(f"| {emoji} {sev.name.title()} | {summary[sev]} |")
        return "\n".join(lines)

    def _findings_list(self, result: ScanResult) -> str:
        """Build findings list with details."""
        lines = ["### Findings\n"]
        for finding in result.findings[:10]:  # Limit to first 10
            emoji = self.SEVERITY_EMOJI[finding.severity]
            lines.append(f"**{emoji} {finding.rule_id}** - {finding.message}")
            lines.append(f"`{finding.file_path}:{finding.line_number}`\n")
        if len(result.findings) > 10:
            lines.append(f"*... and {len(result.findings) - 10} more*")
        return "\n".join(lines)
