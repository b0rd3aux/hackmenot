"""Main CLI entry point using Typer."""

import typer

app = typer.Typer(
    name="hackmenot",
    help="AI-Era Code Security Scanner",
    add_completion=False,
)

@app.callback()
def main() -> None:
    """hackmenot - AI-Era Code Security Scanner."""
    pass
