"""Command line interface for Gatekeeper AI built with Typer."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Annotated, Literal

import typer
from rich.console import Console

from gatekeeper import __version__
from gatekeeper.config import (
    DEFAULT_CONFIG_YAML,
    LENIENT_PRESET_YAML,
    STRICT_PRESET_YAML,
    load_config,
)
from gatekeeper.engine.audit import run_audit
from gatekeeper.llm.client import PROMPT_VERSION
from gatekeeper.models import AuditResult, Verdict
from gatekeeper.platforms import detect_platform
from gatekeeper.report import (
    generate_html_report,
    generate_markdown_report,
    generate_sarif_report,
)

app = typer.Typer(
    name="gatekeeper",
    help="Gatekeeper AI - AI-powered quality gate for pull requests.",
    no_args_is_help=True,
)
baseline_app = typer.Typer(name="baseline", help="Manage baseline suppressions.")
app.add_typer(baseline_app)

console = Console()


@app.command()
def audit(
    base: Annotated[
        str | None, typer.Option("--base", help="Base ref/branch for comparison")
    ] = None,
    head: Annotated[
        str | None, typer.Option("--head", help="Head ref/branch for comparison")
    ] = None,
    config: Annotated[
        Path | None, typer.Option("--config", "-c", help="Path to config file")
    ] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Simulate audit without calling Claude")
    ] = False,
    mock: Annotated[bool, typer.Option("--mock", help="Use deterministic mock LLM")] = False,
    publish_url: Annotated[
        str | None, typer.Option("--publish-url", help="HTTP endpoint to POST audit report to")
    ] = None,
    publish_token: Annotated[
        str | None, typer.Option("--publish-token", help="Bearer token for HTTP report publishing")
    ] = None,
) -> None:
    """Run code audit on pull request or local commit range."""
    # Load configuration
    try:
        cfg = load_config(config)
    except Exception as e:
        console.print(f"[bold red]Configuration Error:[/bold red] {e}")
        raise typer.Exit(code=2) from None

    # Detect platform
    try:
        platform = detect_platform(
            base=base,
            head=head,
            context_lines=cfg.review.context_lines,
        )
    except Exception as e:
        console.print(f"[bold red]Platform Detection Error:[/bold red] {e}")
        raise typer.Exit(code=2) from None

    try:
        result = run_audit(
            platform=platform,
            config=cfg,
            base=base,
            head=head,
            dry_run=dry_run,
            mock=mock,
            publish_url=publish_url,
            publish_token=publish_token,
        )
    except Exception as e:
        console.print(f"[bold red]Audit Execution Error:[/bold red] {e}")
        raise typer.Exit(code=2) from None

    if result.verdict == Verdict.PASS or result.verdict == Verdict.SKIPPED:
        raise typer.Exit(code=0)
    elif result.verdict == Verdict.FAIL:
        raise typer.Exit(code=1)
    else:
        raise typer.Exit(code=2)


@app.command()
def init(
    preset: Annotated[
        Literal["strict", "balanced", "lenient"],
        typer.Option("--preset", "-p", help="Configuration preset"),
    ] = "balanced",
) -> None:
    """Initialize a starter gatekeeper.yml and CI configuration."""
    target_config = Path("gatekeeper.yml")
    if target_config.exists():
        console.print(
            f"[yellow]Warning: {target_config} already exists. Skipping config write.[/yellow]"
        )
    else:
        content_map = {
            "strict": STRICT_PRESET_YAML,
            "balanced": DEFAULT_CONFIG_YAML,
            "lenient": LENIENT_PRESET_YAML,
        }
        yaml_content = content_map.get(preset, DEFAULT_CONFIG_YAML)
        target_config.write_text(yaml_content, encoding="utf-8")
        console.print(f"[green]Created {target_config} with '{preset}' preset.[/green]")

    # Check if inside git and recommend CI workflow
    gh_dir = Path(".github/workflows")
    if gh_dir.exists():
        sample_wf = gh_dir / "gatekeeper.yml"
        if not sample_wf.exists():
            console.print(
                "[cyan]GitHub Actions detected. You can add a workflow file in .github/workflows/gatekeeper.yml[/cyan]"
            )


@app.command(name="validate-config")
def validate_config(
    config: Annotated[
        Path | None, typer.Option("--config", "-c", help="Path to config file")
    ] = None,
) -> None:
    """Validate gatekeeper.yml structure and check for required environment variables."""
    target = config or Path("gatekeeper.yml")
    if not target.exists():
        console.print(f"[bold red]Config file not found:[/bold red] {target}")
        raise typer.Exit(code=2)

    try:
        cfg = load_config(target)
    except Exception as e:
        console.print(f"[bold red]Invalid configuration in {target}:[/bold red] {e}")
        raise typer.Exit(code=2) from None

    console.print(f"[green]Configuration {target} is valid![/green]")

    # Check environment variable requirements
    warnings: list[str] = []
    if not os.environ.get("ANTHROPIC_API_KEY"):
        warnings.append(
            "ANTHROPIC_API_KEY environment variable is not set (required for Claude passes)."
        )

    if cfg.notify.slack.webhook_env and not os.environ.get(cfg.notify.slack.webhook_env):
        warnings.append(f"Slack webhook env '{cfg.notify.slack.webhook_env}' is not set.")

    if cfg.notify.teams.webhook_env and not os.environ.get(cfg.notify.teams.webhook_env):
        warnings.append(f"Teams webhook env '{cfg.notify.teams.webhook_env}' is not set.")

    if warnings:
        console.print("\n[yellow]Environment Warnings:[/yellow]")
        for w in warnings:
            console.print(f"  - {w}")
    else:
        console.print("[green]All primary environment variables are present.[/green]")


@baseline_app.command(name="create")
def baseline_create(
    config: Annotated[
        Path | None, typer.Option("--config", "-c", help="Path to config file")
    ] = None,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Baseline output path")
    ] = None,
    mock: Annotated[bool, typer.Option("--mock", help="Use mock LLM for baseline")] = False,
) -> None:
    """Audit current repository changes or HEAD and save findings as baseline."""
    cfg = load_config(config)
    target_file = output or Path(cfg.suppressions.baseline_file)
    target_file.parent.mkdir(parents=True, exist_ok=True)

    platform = detect_platform(context_lines=cfg.review.context_lines)
    result = run_audit(platform=platform, config=cfg, mock=mock)

    baseline_data = {
        "tool_version": __version__,
        "created_at": result.metadata.start_time,
        "findings": [f.model_dump() for f in result.findings],
    }
    target_file.write_text(json.dumps(baseline_data, indent=2), encoding="utf-8")
    console.print(
        f"[green]Saved {len(result.findings)} findings to baseline: {target_file}[/green]"
    )


@app.command(name="report")
def rebuild_report(
    from_file: Annotated[Path, typer.Option("--from", help="Input report.json path")] = Path(
        "gatekeeper-report/report.json"
    ),
    format: Annotated[
        str, typer.Option("--format", help="Target output format (html, markdown, sarif)")
    ] = "html",
    out: Annotated[Path | None, typer.Option("--out", help="Output file path")] = None,
) -> None:
    """Rebuild visual reports from an existing report.json file."""
    if not from_file.exists():
        console.print(f"[bold red]File not found:[/bold red] {from_file}")
        raise typer.Exit(code=2)

    data = json.loads(from_file.read_text(encoding="utf-8"))
    res = AuditResult.model_validate(data)

    fmt = format.lower()
    if fmt == "html":
        target = out or Path("gatekeeper-report/report.html")
        generate_html_report(res, target)
        console.print(f"[green]Generated HTML report at {target}[/green]")
    elif fmt in ("markdown", "md"):
        target = out or Path("gatekeeper-report/report.md")
        generate_markdown_report(res, target)
        console.print(f"[green]Generated Markdown report at {target}[/green]")
    elif fmt == "sarif":
        target = out or Path("gatekeeper-report/report.sarif")
        generate_sarif_report(res, target)
        console.print(f"[green]Generated SARIF report at {target}[/green]")
    else:
        console.print(f"[bold red]Unsupported format:[/bold red] {format}")
        raise typer.Exit(code=2)


@app.command()
def version() -> None:
    """Display Gatekeeper AI tool, prompt, and schema versions."""
    console.print(f"Gatekeeper AI version: [bold cyan]{__version__}[/bold cyan]")
    console.print(f"Prompt template version: [bold cyan]{PROMPT_VERSION}[/bold cyan]")
    console.print("Config schema version: [bold cyan]1[/bold cyan]")
