"""Main CLI entry point using Typer."""

from pathlib import Path

import typer
from rich.console import Console

from hackmenot import __version__

app = typer.Typer(
    name="hackmenot",
    help="AI-Era Code Security Scanner",
    add_completion=False,
)
console = Console()


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
        exists=True,
    ),
    format: str = typer.Option(
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal, json, sarif",
    ),
) -> None:
    """Scan code for security vulnerabilities."""
    console.print(f"[cyan]Scanning {len(paths)} path(s)...[/cyan]")
    # TODO: Implement scanning
    console.print("[green]Scan complete (no rules implemented yet)[/green]")


@app.command()
def rules() -> None:
    """List available security rules."""
    console.print("[yellow]No rules implemented yet[/yellow]")
