"""Main CLI entry point using Typer."""

import json
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console

from hackmenot import __version__
from hackmenot.cli.interactive import (
    InteractiveFixer,
    apply_fixes_auto,
    write_fixed_files,
)
from hackmenot.core.config import ConfigLoader
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
    fix: bool = typer.Option(
        False,
        "--fix",
        help="Automatically apply all available fixes",
    ),
    fix_interactive: bool = typer.Option(
        False,
        "--fix-interactive",
        help="Interactively apply fixes (prompt for each)",
    ),
    full: bool = typer.Option(
        False,
        "--full",
        help="Bypass cache, perform full scan",
    ),
    config_file: Path | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to config file",
    ),
) -> None:
    """Scan code for security vulnerabilities."""
    # Validate --fix and --fix-interactive are mutually exclusive
    if fix and fix_interactive:
        console.print(
            "[red]Error: --fix and --fix-interactive cannot be used together[/red]"
        )
        raise typer.Exit(1)

    # Validate paths exist
    for path in paths:
        if not path.exists():
            console.print(f"[red]Error: Path does not exist: {path}[/red]")
            raise typer.Exit(1)

    # Load configuration
    config_loader = ConfigLoader()
    if config_file is not None:
        if not config_file.exists():
            console.print(f"[red]Error: Config file not found: {config_file}[/red]")
            raise typer.Exit(1)
        config = config_loader.load_from_file(config_file)
    else:
        # Use current directory or first path's parent for config discovery
        project_dir = paths[0].parent if paths[0].is_file() else paths[0]
        config = config_loader.load(project_dir)

    # Parse severity levels (CLI args override config)
    try:
        min_severity = Severity.from_string(severity)
        # Use config fail_on if not explicitly set on CLI
        effective_fail_on = fail_on if fail_on != "high" else config.fail_on
        fail_severity = Severity.from_string(effective_fail_on)
    except KeyError as e:
        console.print(f"[red]Error: Invalid severity level: {e}[/red]")
        raise typer.Exit(1)

    # Run scan (bypass cache if --full is set)
    scanner = Scanner()
    result = scanner.scan(paths, min_severity=min_severity, use_cache=not full)

    # Output results (before applying fixes)
    if format == OutputFormat.terminal:
        reporter = TerminalReporter(console=console)
        reporter.render(result)
    elif format == OutputFormat.json:
        _output_json(result)
    elif format == OutputFormat.sarif:
        console.print("[yellow]SARIF output not yet implemented[/yellow]")
        _output_json(result)

    # Handle fix modes
    if (fix or fix_interactive) and result.has_findings:
        # Read file contents for findings
        original_contents: dict[str, str] = {}
        for finding in result.findings:
            if finding.file_path not in original_contents:
                try:
                    original_contents[finding.file_path] = Path(
                        finding.file_path
                    ).read_text()
                except OSError as e:
                    console.print(
                        f"[red]Error reading {finding.file_path}: {e}[/red]"
                    )

        if fix_interactive:
            # Interactive mode
            fixer = InteractiveFixer(console=console)
            modified_contents = fixer.run(result.findings, original_contents)
        else:
            # Auto-fix mode
            modified_contents, _ = apply_fixes_auto(
                result.findings, original_contents, console=console
            )

        # Write modified files back to disk
        files_written = write_fixed_files(modified_contents, original_contents)
        if files_written > 0:
            console.print(f"[green]Modified {files_written} file(s)[/green]")

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
