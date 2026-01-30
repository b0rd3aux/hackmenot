"""Terminal reporter with Rich colored output."""

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from hackmenot import __version__
from hackmenot.core.models import Finding, ScanResult, Severity
from hackmenot.reporters.base import BaseReporter


class TerminalReporter(BaseReporter):
    """Rich terminal reporter with colors."""

    SEVERITY_STYLES = {
        Severity.CRITICAL: ("bright_red", "CRITICAL", "bold bright_red"),
        Severity.HIGH: ("yellow", "HIGH", "bold yellow"),
        Severity.MEDIUM: ("bright_yellow", "MEDIUM", "bright_yellow"),
        Severity.LOW: ("green", "LOW", "dim green"),
    }

    SEVERITY_COLORS = {
        Severity.CRITICAL: "red",
        Severity.HIGH: "yellow",
        Severity.MEDIUM: "bright_yellow",
        Severity.LOW: "green",
    }

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def render(self, result: ScanResult) -> None:
        """Render scan results to terminal."""
        self._render_header()

        if result.has_findings:
            self._render_findings(result.findings)
        else:
            self._render_no_findings()

        self._render_summary(result)

    def _render_header(self) -> None:
        """Render the header banner."""
        header = Text()
        header.append("  ", style="bold")
        header.append("hackmenot", style="bold cyan")
        header.append(f" v{__version__}", style="dim")
        header.append(" - AI-Era Code Security Scanner", style="dim")

        self.console.print()
        self.console.print(header)
        self.console.rule(style="dim")

    def _render_findings(self, findings: list[Finding]) -> None:
        """Render all findings."""
        # Group by file
        by_file: dict[str, list[Finding]] = {}
        for finding in findings:
            by_file.setdefault(finding.file_path, []).append(finding)

        for file_path, file_findings in by_file.items():
            # Sort by line number
            file_findings.sort(key=lambda f: f.line_number)

            for finding in file_findings:
                self._render_finding(finding)

    def _render_finding(self, finding: Finding) -> None:
        """Render a single finding."""
        _, label, label_style = self.SEVERITY_STYLES[finding.severity]

        # Header line
        header = Text()
        header.append("X ", style="bold red")
        header.append(label, style=label_style)
        header.append("  ", style="default")
        header.append(finding.file_path, style="cyan")
        header.append(":", style="dim")
        header.append(str(finding.line_number), style="magenta")

        self.console.print()
        self.console.print(Panel(
            header,
            box=box.ROUNDED,
            border_style="dim",
            padding=(0, 1),
        ))

        # Rule info
        rule_line = Text()
        rule_line.append(f"  {finding.rule_id}", style="yellow")
        rule_line.append(": ", style="dim")
        rule_line.append(finding.message, style="default")
        self.console.print(rule_line)

        # Code snippet
        self.console.print()
        code_text = Text()
        code_text.append("    -> ", style="yellow")
        code_text.append(finding.code_snippet, style="default on bright_black")
        self.console.print(code_text)

        # Fix suggestion
        if finding.fix_suggestion:
            self.console.print()
            fix_text = Text()
            fix_text.append("    Fix: ", style="bold green")
            fix_text.append(finding.fix_suggestion.split('\n')[0], style="green")
            self.console.print(fix_text)

        # Education
        if finding.education:
            edu_text = Text()
            edu_text.append("    Why: ", style="bold blue")
            edu_text.append(finding.education.split('\n')[0], style="dim italic")
            self.console.print(edu_text)

    def _render_no_findings(self) -> None:
        """Render message when no findings."""
        self.console.print()
        self.console.print(
            "  [bold green]No issues found![/bold green]",
        )

    def _render_summary(self, result: ScanResult) -> None:
        """Render summary section."""
        self.console.print()
        self.console.rule("Summary", style="dim")
        self.console.print()

        # Stats line
        stats = Text()
        stats.append("  Files scanned: ", style="dim")
        stats.append(str(result.files_scanned), style="bold")
        stats.append("    Time: ", style="dim")
        time_style = "green" if result.scan_time_ms < 1000 else "yellow"
        stats.append(f"{result.scan_time_ms:.0f}ms", style=time_style)
        self.console.print(stats)

        # Severity counts
        summary = result.summary_by_severity()

        counts = Text()
        counts.append("  ")
        counts.append("●", style=self.SEVERITY_COLORS[Severity.CRITICAL])
        counts.append(" Critical: ", style="default")
        counts.append(str(summary[Severity.CRITICAL]), style="bold red")
        counts.append("  ")
        counts.append("●", style=self.SEVERITY_COLORS[Severity.HIGH])
        counts.append(" High: ", style="default")
        counts.append(str(summary[Severity.HIGH]), style="bold yellow")
        counts.append("  ")
        counts.append("●", style=self.SEVERITY_COLORS[Severity.MEDIUM])
        counts.append(" Medium: ", style="default")
        counts.append(str(summary[Severity.MEDIUM]), style="bright_yellow")
        counts.append("  ")
        counts.append("●", style=self.SEVERITY_COLORS[Severity.LOW])
        counts.append(" Low: ", style="default")
        counts.append(str(summary[Severity.LOW]), style="dim green")

        self.console.print()
        self.console.print(counts)

        # Suggestion
        if result.has_findings:
            self.console.print()
            self.console.print(
                "  [dim]-> Run[/dim] [cyan]hackmenot scan . --fix-interactive[/cyan] "
                "[dim]to fix issues[/dim]"
            )

        self.console.print()
