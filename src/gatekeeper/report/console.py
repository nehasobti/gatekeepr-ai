"""Rich console output reporting for Gatekeeper AI."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from gatekeeper.models import AuditResult, Severity, Verdict

console = Console()


def print_console_report(result: AuditResult) -> None:
    """Print beautifully styled audit results to stdout using Rich."""
    console.print()
    # Header summary
    title = f"Gatekeeper AI Audit Report - [bold]{result.verdict.value}[/bold]"
    border_color = (
        "green"
        if result.verdict == Verdict.PASS
        else "yellow"
        if result.verdict == Verdict.SKIPPED
        else "red"
    )

    summary_text = (
        f"Critical: [bold red]{result.summary.critical}[/bold red] | "
        f"High: [bold dark_orange]{result.summary.high}[/bold dark_orange] | "
        f"Medium: [bold yellow]{result.summary.medium}[/bold yellow] | "
        f"Low: [bold blue]{result.summary.low}[/bold blue] | "
        f"Info: [bold cyan]{result.summary.info}[/bold cyan] | "
        f"Total: [bold]{result.summary.total}[/bold]"
    )
    console.print(Panel(summary_text, title=title, border_style=border_color))

    # Findings Table
    if result.findings:
        table = Table(title="Detected Findings", show_lines=True)
        table.add_column("Severity", justify="center", style="bold")
        table.add_column("Location", style="cyan")
        table.add_column("Category", style="magenta")
        table.add_column("Title / Explanation", style="white")
        table.add_column("Source", style="dim")

        for f in result.findings:
            sev_color = {
                Severity.CRITICAL: "[bold red]CRITICAL[/bold red]",
                Severity.HIGH: "[bold dark_orange]HIGH[/bold dark_orange]",
                Severity.MEDIUM: "[yellow]MEDIUM[/yellow]",
                Severity.LOW: "[blue]LOW[/blue]",
                Severity.INFO: "[cyan]INFO[/cyan]",
            }.get(f.severity, f.severity.value)

            loc = f"{f.file}:{f.start_line}"
            if f.end_line > f.start_line:
                loc += f"-{f.end_line}"

            sources = ", ".join(f.source)
            text = f"[bold]{f.title}[/bold]\n{f.explanation}"

            table.add_row(sev_color, loc, f.category.value, text, sources)

        console.print(table)
    else:
        if result.verdict == Verdict.PASS:
            console.print(
                "[bold green]PASSED: No blocking issues found. Code is safe to merge![/bold green]"
            )
        elif result.verdict == Verdict.SKIPPED:
            console.print("[yellow]Audit skipped: branch is not in target_branches.[/yellow]")

    # Meta
    meta = result.metadata
    meta_info = (
        f"Duration: {meta.duration_seconds:.2f}s | "
        f"Tokens (in/out/cached): {meta.input_tokens}/{meta.output_tokens}/{meta.cached_tokens} | "
        f"Cost: ${meta.estimated_cost_usd:.4f}"
    )
    if meta.skipped_files:
        meta_info += f" | Skipped files: {len(meta.skipped_files)}"

    console.print(f"[dim]{meta_info}[/dim]\n")
