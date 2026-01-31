"""Unified diff generator for fix previews."""

from dataclasses import dataclass
import difflib
from rich.console import Console
from rich.text import Text


@dataclass
class FileDiff:
    """Diff for a single file."""
    file_path: str
    original: str
    modified: str

    def has_changes(self) -> bool:
        """Check if there are any changes."""
        return self.original != self.modified

    def unified_diff(self, context_lines: int = 3) -> list[str]:
        """Generate unified diff lines."""
        original_lines = self.original.splitlines(keepends=True)
        modified_lines = self.modified.splitlines(keepends=True)

        return list(difflib.unified_diff(
            original_lines,
            modified_lines,
            fromfile=f"a/{self.file_path}",
            tofile=f"b/{self.file_path}",
            n=context_lines,
        ))


class DiffGenerator:
    """Generates and displays unified diffs."""

    def __init__(self, console: Console | None = None):
        self.console = console or Console()

    def generate_diffs(
        self,
        original_contents: dict[str, str],
        modified_contents: dict[str, str]
    ) -> list[FileDiff]:
        """Generate diffs for all modified files."""
        diffs = []
        for file_path, modified in modified_contents.items():
            original = original_contents.get(file_path, "")
            diff = FileDiff(file_path, original, modified)
            if diff.has_changes():
                diffs.append(diff)
        return diffs

    def print_summary(self, diffs: list[FileDiff]) -> None:
        """Print summary of changes."""
        if not diffs:
            self.console.print("[green]No fixes to apply.[/green]")
            return

        total_files = len(diffs)
        self.console.print(f"\n[bold]Found fixes in {total_files} file(s):[/bold]\n")

        for diff in diffs:
            # Count changed lines
            additions = 0
            deletions = 0
            for line in diff.unified_diff():
                if line.startswith('+') and not line.startswith('+++'):
                    additions += 1
                elif line.startswith('-') and not line.startswith('---'):
                    deletions += 1

            self.console.print(f"  {diff.file_path} [green]+{additions}[/green] [red]-{deletions}[/red]")

    def print_diff(self, diffs: list[FileDiff]) -> None:
        """Print full unified diff with syntax highlighting."""
        if not diffs:
            self.console.print("[green]No changes to display.[/green]")
            return

        for diff in diffs:
            self.console.print(f"\n[bold]── {diff.file_path} ──[/bold]")

            for line in diff.unified_diff():
                line = line.rstrip('\n')
                if line.startswith('+++') or line.startswith('---'):
                    self.console.print(f"[bold]{line}[/bold]")
                elif line.startswith('@@'):
                    self.console.print(f"[cyan]{line}[/cyan]")
                elif line.startswith('+'):
                    self.console.print(f"[green]{line}[/green]")
                elif line.startswith('-'):
                    self.console.print(f"[red]{line}[/red]")
                else:
                    self.console.print(line)

    def format_diff_plain(self, diffs: list[FileDiff]) -> str:
        """Return plain text diff without colors."""
        lines = []
        for diff in diffs:
            lines.append(f"── {diff.file_path} ──")
            lines.extend(line.rstrip('\n') for line in diff.unified_diff())
            lines.append("")
        return "\n".join(lines)
