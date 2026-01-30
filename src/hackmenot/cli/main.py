"""Main CLI entry point using Typer."""

import json
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console

from hackmenot import __version__
from hackmenot.core.models import ScanResult, Severity
from hackmenot.core.scanner import Scanner
from hackmenot.reporters.terminal import TerminalReporter

app = typer.Typer(
    name="hackmenot",
    help="AI-Era Code Security Scanner",
    add_completion=False,
)
console = Console()


class OutputFormat(str, Enum):
    """Output format options."""
    terminal = "terminal"
    json = "json"
    sarif = "sarif"


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"hackmenot {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool | None = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """hackmenot - AI-Era Code Security Scanner."""
    pass


@app.command()
def scan(
    paths: list[Path] = typer.Argument(
        ...,
        help="Paths to scan (files or directories)",
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.terminal,
        "--format",
        "-f",
        help="Output format",
    ),
    severity: str = typer.Option(
        "low",
        "--severity",
        "-s",
        help="Minimum severity to report: critical, high, medium, low",
    ),
    fail_on: str = typer.Option(
        "high",
        "--fail-on",
        help="Minimum severity to return non-zero exit code",
    ),
) -> None:
    """Scan code for security vulnerabilities."""
    # Validate paths exist
    for path in paths:
        if not path.exists():
            console.print(f"[red]Error: Path does not exist: {path}[/red]")
            raise typer.Exit(1)

    # Parse severity levels
    try:
        min_severity = Severity.from_string(severity)
        fail_severity = Severity.from_string(fail_on)
    except KeyError as e:
        console.print(f"[red]Error: Invalid severity level: {e}[/red]")
        raise typer.Exit(1)

    # Run scan
    scanner = Scanner()
    result = scanner.scan(paths, min_severity=min_severity)

    # Output results
    if format == OutputFormat.terminal:
        reporter = TerminalReporter(console=console)
        reporter.render(result)
    elif format == OutputFormat.json:
        _output_json(result)
    elif format == OutputFormat.sarif:
        console.print("[yellow]SARIF output not yet implemented[/yellow]")
        _output_json(result)

    # Exit code based on findings
    if result.findings_at_or_above(fail_severity):
        raise typer.Exit(1)


def _output_json(result: ScanResult) -> None:
    """Output results as JSON."""
    data = {
        "files_scanned": result.files_scanned,
        "scan_time_ms": result.scan_time_ms,
        "findings": [
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "severity": str(f.severity),
                "message": f.message,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "column": f.column,
                "code_snippet": f.code_snippet,
                "fix_suggestion": f.fix_suggestion,
                "education": f.education,
            }
            for f in result.findings
        ],
        "summary": {
            str(sev): count
            for sev, count in result.summary_by_severity().items()
        },
    }
    print(json.dumps(data, indent=2))


@app.command()
def rules(
    show_id: str | None = typer.Argument(
        None,
        help="Rule ID to show details for",
    ),
) -> None:
    """List available security rules."""
    from hackmenot.rules.registry import RuleRegistry

    registry = RuleRegistry()
    registry.load_all()

    if show_id:
        rule = registry.get_rule(show_id)
        if rule:
            console.print(f"\n[bold cyan]{rule.id}[/bold cyan]: {rule.name}")
            console.print(f"[dim]Severity:[/dim] {rule.severity}")
            console.print(f"[dim]Category:[/dim] {rule.category}")
            console.print(f"\n{rule.description}")
            if rule.education:
                console.print(f"\n[blue]Education:[/blue]\n{rule.education}")
        else:
            console.print(f"[red]Rule not found: {show_id}[/red]")
    else:
        console.print("\n[bold]Available Rules[/bold]\n")
        for rule in registry.get_all_rules():
            sev_color = {
                Severity.CRITICAL: "red",
                Severity.HIGH: "yellow",
                Severity.MEDIUM: "bright_yellow",
                Severity.LOW: "green",
            }[rule.severity]
            console.print(
                f"  [{sev_color}]{rule.severity.name:8}[/{sev_color}] "
                f"[cyan]{rule.id}[/cyan] - {rule.name}"
            )
