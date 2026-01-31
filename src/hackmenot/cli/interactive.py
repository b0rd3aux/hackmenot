"""Interactive fix mode for CLI."""

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.syntax import Syntax

from hackmenot.core.models import Finding
from hackmenot.fixes.engine import FixEngine
from hackmenot.rules.registry import RuleRegistry


class InteractiveFixer:
    """Interactive fixer that prompts user for each finding."""

    def __init__(self, console: Console | None = None):
        """Initialize the interactive fixer.

        Args:
            console: Rich console for output. Creates new one if not provided.
        """
        self.console = console or Console()
        self.engine = FixEngine()
        # Load rules for pattern-based fixes
        registry = RuleRegistry()
        registry.load_all()
        self.rules = {rule.id: rule for rule in registry.get_all_rules()}

    def run(
        self, findings: list[Finding], file_contents: dict[str, str]
    ) -> dict[str, str]:
        """Run interactive fix mode.

        Shows each finding with its fix suggestion and prompts the user
        for action: [a]pply, [s]kip, [A]pply all, [q]uit.

        Args:
            findings: List of findings to potentially fix.
            file_contents: Dictionary mapping file paths to their contents.

        Returns:
            Dictionary mapping file paths to their (potentially modified) contents.
        """
        result = dict(file_contents)
        apply_all = False

        # Group findings by file and sort by line number descending
        # (so we can apply fixes without line number shifts)
        findings_by_file: dict[str, list[Finding]] = {}
        for finding in findings:
            if finding.fix_suggestion:
                if finding.file_path not in findings_by_file:
                    findings_by_file[finding.file_path] = []
                findings_by_file[finding.file_path].append(finding)

        # Sort each file's findings by line number descending
        for file_path in findings_by_file:
            findings_by_file[file_path].sort(
                key=lambda f: f.line_number, reverse=True
            )

        total_findings = sum(len(f) for f in findings_by_file.values())
        current = 0

        for file_path, file_findings in findings_by_file.items():
            for finding in file_findings:
                current += 1

                if apply_all:
                    # Apply without prompting
                    self._apply_fix(finding, result)
                    continue

                # Show finding details
                self._show_finding(finding, current, total_findings)

                # Prompt for action
                action = Prompt.ask(
                    "[bold cyan]Action[/bold cyan]",
                    choices=["a", "s", "A", "q"],
                    default="s",
                )

                if action == "q":
                    self.console.print("[yellow]Quit - stopping fix mode[/yellow]")
                    return result
                elif action == "A":
                    self.console.print(
                        "[green]Applying all remaining fixes...[/green]"
                    )
                    apply_all = True
                    self._apply_fix(finding, result)
                elif action == "a":
                    self._apply_fix(finding, result)
                    self.console.print("[green]Fix applied[/green]")
                else:  # "s"
                    self.console.print("[dim]Skipped[/dim]")

        self.console.print("\n[bold green]Done![/bold green] Interactive fix mode complete.")
        return result

    def _show_finding(
        self, finding: Finding, current: int, total: int
    ) -> None:
        """Display a finding with its fix suggestion.

        Args:
            finding: The finding to display.
            current: Current finding number.
            total: Total number of findings.
        """
        self.console.print()
        self.console.print(
            f"[bold]Finding {current}/{total}[/bold] - "
            f"[cyan]{finding.rule_id}[/cyan]: {finding.rule_name}"
        )
        self.console.print(
            f"[dim]{finding.file_path}:{finding.line_number}[/dim]"
        )
        self.console.print()

        # Show the problematic code
        self.console.print("[bold red]Current code:[/bold red]")
        syntax = Syntax(
            finding.code_snippet,
            "python",
            theme="monokai",
            line_numbers=False,
        )
        self.console.print(syntax)
        self.console.print()

        # Show the fix suggestion
        self.console.print("[bold green]Suggested fix:[/bold green]")
        fix_syntax = Syntax(
            finding.fix_suggestion,
            "python",
            theme="monokai",
            line_numbers=False,
        )
        self.console.print(fix_syntax)
        self.console.print()

        self.console.print(
            "[dim]\\[a]pply  \\[s]kip  \\[A]pply all  \\[q]uit[/dim]"
        )

    def _apply_fix(
        self, finding: Finding, file_contents: dict[str, str]
    ) -> None:
        """Apply a fix to the file contents.

        Args:
            finding: The finding with the fix to apply.
            file_contents: Dictionary of file contents to modify in place.
        """
        if finding.file_path in file_contents:
            source = file_contents[finding.file_path]
            rule = self.rules.get(finding.rule_id)
            result = self.engine.apply_fix(source, finding, rule)
            if result.applied:
                # Rebuild source with the fix applied
                lines = source.split("\n")
                line_idx = finding.line_number - 1
                if 0 <= line_idx < len(lines):
                    fixed_lines = result.fixed.split("\n")
                    lines[line_idx : line_idx + 1] = fixed_lines
                    file_contents[finding.file_path] = "\n".join(lines)


def apply_fixes_auto(
    findings: list[Finding],
    file_contents: dict[str, str],
    console: Console | None = None,
) -> tuple[dict[str, str], int]:
    """Apply all fixes automatically.

    Args:
        findings: List of findings to fix.
        file_contents: Dictionary mapping file paths to their contents.
        console: Rich console for output.

    Returns:
        Tuple of (modified file contents dict, number of fixes applied).
    """
    console = console or Console()
    engine = FixEngine()
    result = dict(file_contents)
    total_applied = 0

    # Load rules for pattern-based fixes
    registry = RuleRegistry()
    registry.load_all()
    rules = {rule.id: rule for rule in registry.get_all_rules()}

    # Group findings by file
    findings_by_file: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.fix_suggestion:
            if finding.file_path not in findings_by_file:
                findings_by_file[finding.file_path] = []
            findings_by_file[finding.file_path].append(finding)

    for file_path, file_findings in findings_by_file.items():
        if file_path in result:
            fixed, count = engine.apply_fixes(result[file_path], file_findings, rules)
            result[file_path] = fixed
            total_applied += count

    if total_applied > 0:
        console.print(f"[green]Applied {total_applied} fix(es)[/green]")
    else:
        console.print("[yellow]No fixes to apply[/yellow]")

    return result, total_applied


def write_fixed_files(
    file_contents: dict[str, str], original_contents: dict[str, str]
) -> int:
    """Write modified files back to disk.

    Only writes files that have been modified.

    Args:
        file_contents: Dictionary of (potentially) modified file contents.
        original_contents: Dictionary of original file contents.

    Returns:
        Number of files written.
    """
    written = 0
    for file_path, content in file_contents.items():
        if content != original_contents.get(file_path):
            Path(file_path).write_text(content)
            written += 1
    return written
