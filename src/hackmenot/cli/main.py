"""Main CLI entry point using Typer."""

import json
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console

from hackmenot import __version__
from hackmenot.cli.git import get_changed_files, get_staged_files, is_git_repo
from hackmenot.cli.interactive import (
    InteractiveFixer,
    apply_fixes_auto,
    write_fixed_files,
)
from hackmenot.fixes.diff import DiffGenerator
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
    paths: list[Path] | None = typer.Argument(
        None,
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
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Preview fixes without applying them (requires --fix)",
    ),
    diff: bool = typer.Option(
        False,
        "--diff",
        help="Show unified diff output (requires --fix --dry-run)",
    ),
    full: bool = typer.Option(
        False,
        "--full",
        help="Bypass cache, perform full scan",
    ),
    ci: bool = typer.Option(
        False,
        "--ci",
        help="CI-friendly output (no colors, machine-readable exit codes)",
    ),
    staged: bool = typer.Option(
        False,
        "--staged",
        help="Scan only git staged files (for pre-commit hooks)",
    ),
    changed_since: str | None = typer.Option(
        None,
        "--changed-since",
        help="Only scan files changed since this git ref (commit, branch, tag)",
    ),
    pr_comment: bool = typer.Option(
        False,
        "--pr-comment",
        help="Output markdown for PR comments",
    ),
    config_file: Path | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to config file",
    ),
    include_deps: bool = typer.Option(
        False,
        "--include-deps",
        help="Also scan dependency files for security issues",
    ),
) -> None:
    """Scan code for security vulnerabilities."""
    # Use CI-friendly console if --ci flag is set
    scan_console = Console(force_terminal=False, no_color=True) if ci else console

    # Validate --fix and --fix-interactive are mutually exclusive
    if fix and fix_interactive:
        scan_console.print(
            "Error: --fix and --fix-interactive cannot be used together"
        )
        raise typer.Exit(1)

    # Validate --staged and --changed-since are mutually exclusive
    if staged and changed_since:
        scan_console.print(
            "Error: --staged and --changed-since cannot be used together"
        )
        raise typer.Exit(1)

    # Validate --dry-run requires --fix
    if dry_run and not fix:
        scan_console.print(
            "Error: --dry-run requires --fix"
        )
        raise typer.Exit(1)

    # Validate --diff requires --dry-run
    if diff and not dry_run:
        scan_console.print(
            "Error: --diff requires --dry-run"
        )
        raise typer.Exit(1)

    # Handle --staged flag
    if staged:
        if not is_git_repo():
            scan_console.print("Error: --staged requires a git repository")
            raise typer.Exit(1)

        staged_files = get_staged_files()
        if not staged_files:
            scan_console.print("No staged files to scan")
            raise typer.Exit(0)

        # Filter to supported extensions
        supported_extensions = Scanner.SUPPORTED_EXTENSIONS
        scan_paths = [
            f for f in staged_files
            if f.suffix in supported_extensions and f.exists()
        ]

        if not scan_paths:
            scan_console.print("No supported files in staged changes")
            raise typer.Exit(0)
    # Handle --changed-since flag
    elif changed_since:
        if not is_git_repo():
            scan_console.print("Error: --changed-since requires a git repository")
            raise typer.Exit(1)

        changed_files = get_changed_files(changed_since)
        if not changed_files:
            scan_console.print(f"No files changed since {changed_since}")
            raise typer.Exit(0)

        # Filter to supported extensions and existing files
        supported_extensions = Scanner.SUPPORTED_EXTENSIONS
        scan_paths = [
            f for f in changed_files
            if f.suffix in supported_extensions and f.exists()
        ]

        if not scan_paths:
            scan_console.print("No supported files in changes")
            raise typer.Exit(0)
    else:
        # Use provided paths
        if not paths:
            scan_console.print("Error: No paths provided")
            raise typer.Exit(1)
        scan_paths = list(paths)

    # Validate paths exist
    for path in scan_paths:
        if not path.exists():
            scan_console.print(f"Error: Path does not exist: {path}")
            raise typer.Exit(1)

    try:
        # Load configuration
        config_loader = ConfigLoader()
        if config_file is not None:
            if not config_file.exists():
                scan_console.print(f"Error: Config file not found: {config_file}")
                raise typer.Exit(1)
            config = config_loader.load_from_file(config_file)
        else:
            # Use current directory or first path's parent for config discovery
            project_dir = scan_paths[0].parent if scan_paths[0].is_file() else scan_paths[0]
            config = config_loader.load(project_dir)

        # Parse severity levels (CLI args override config)
        try:
            min_severity = Severity.from_string(severity)
            # Use config fail_on if not explicitly set on CLI
            effective_fail_on = fail_on if fail_on != "high" else config.fail_on
            fail_severity = Severity.from_string(effective_fail_on)
        except KeyError as e:
            scan_console.print(f"Error: Invalid severity level: {e}")
            raise typer.Exit(1)

        # Run scan (bypass cache if --full is set)
        scanner = Scanner(config=config)
        result = scanner.scan(scan_paths, min_severity=min_severity, use_cache=not full)

        # Include dependency scanning if requested
        if include_deps:
            from hackmenot.deps.scanner import DependencyScanner
            dep_scanner = DependencyScanner()
            project_dir = scan_paths[0].parent if scan_paths[0].is_file() else scan_paths[0]
            dep_result = dep_scanner.scan(project_dir)
            # Merge findings
            result = ScanResult(
                files_scanned=result.files_scanned + dep_result.files_scanned,
                findings=result.findings + dep_result.findings,
                scan_time_ms=result.scan_time_ms + dep_result.scan_time_ms,
            )

        # Output results (before applying fixes)
        if pr_comment:
            from hackmenot.reporters.markdown import MarkdownReporter
            md_reporter = MarkdownReporter()
            print(md_reporter.render(result))
        elif format == OutputFormat.terminal:
            reporter = TerminalReporter(console=scan_console)
            reporter.render(result)
        elif format == OutputFormat.json:
            _output_json(result)
        elif format == OutputFormat.sarif:
            from hackmenot.reporters.sarif import SARIFReporter
            reporter = SARIFReporter()
            print(reporter.render(result))
    except typer.Exit:
        raise
    except Exception as e:
        if ci:
            scan_console.print(f"Error during scan: {e}")
            raise typer.Exit(2)
        raise

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
                    scan_console.print(
                        f"Error reading {finding.file_path}: {e}"
                    )

        if fix_interactive:
            # Interactive mode
            fixer = InteractiveFixer(console=scan_console)
            modified_contents = fixer.run(result.findings, original_contents)
        else:
            # Auto-fix mode (with optional dry-run)
            modified_contents, _ = apply_fixes_auto(
                result.findings, original_contents, console=scan_console if not dry_run else None
            )

        if dry_run:
            # Preview mode: show diffs, don't write files
            diff_gen = DiffGenerator(console=scan_console)
            diffs = diff_gen.generate_diffs(original_contents, modified_contents)
            if diff:
                # Full unified diff output
                diff_gen.print_diff(diffs)
            else:
                # Summary only
                diff_gen.print_summary(diffs)
            if diffs:
                scan_console.print(
                    "\n[dim]Run without --dry-run to apply these fixes.[/dim]"
                )
        else:
            # Write modified files back to disk
            files_written = write_fixed_files(modified_contents, original_contents)
            if files_written > 0:
                scan_console.print(f"Modified {files_written} file(s)")

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


@app.command()
def deps(
    path: Path = typer.Argument(..., help="Directory to scan for dependency files"),
    check_vulns: bool = typer.Option(False, "--check-vulns", help="Check for CVEs via OSV API"),
    format: OutputFormat = typer.Option(OutputFormat.terminal, "--format", "-f", help="Output format"),
    fail_on: str = typer.Option("high", "--fail-on", help="Minimum severity for non-zero exit"),
    ci: bool = typer.Option(False, "--ci", help="CI-friendly output"),
) -> None:
    """Scan dependencies for security issues."""
    from hackmenot.deps.scanner import DependencyScanner

    scan_console = Console(force_terminal=False, no_color=True) if ci else console

    if not path.exists():
        scan_console.print(f"Error: Path does not exist: {path}")
        raise typer.Exit(1)
    if not path.is_dir():
        scan_console.print(f"Error: Path must be a directory: {path}")
        raise typer.Exit(1)

    try:
        scanner = DependencyScanner()
        result = scanner.scan(path, check_vulns=check_vulns)

        if format == OutputFormat.terminal:
            reporter = TerminalReporter(console=scan_console)
            reporter.render(result)
        elif format == OutputFormat.json:
            _output_json(result)
        elif format == OutputFormat.sarif:
            from hackmenot.reporters.sarif import SARIFReporter
            reporter = SARIFReporter()
            print(reporter.render(result))
    except typer.Exit:
        raise
    except Exception as e:
        if ci:
            scan_console.print(f"Error: {e}")
            raise typer.Exit(2)
        raise

    try:
        fail_severity = Severity.from_string(fail_on)
    except KeyError:
        scan_console.print(f"Error: Invalid severity: {fail_on}")
        raise typer.Exit(1)

    if result.findings_at_or_above(fail_severity):
        raise typer.Exit(1)
