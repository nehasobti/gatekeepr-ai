"""Reporting package for Gatekeeper AI."""

from pathlib import Path

from gatekeeper.models import AuditResult
from gatekeeper.report.console import print_console_report
from gatekeeper.report.html import generate_html_report
from gatekeeper.report.json_report import generate_json_report
from gatekeeper.report.markdown import (
    generate_markdown_content,
    generate_markdown_report,
)
from gatekeeper.report.sarif import generate_sarif_report


def write_all_reports(
    result: AuditResult,
    output_dir: str | Path,
    formats: list[str] | None = None,
) -> dict[str, Path]:
    """Write reports in specified formats into the output directory."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    active_formats = formats or ["markdown", "html", "json", "sarif"]
    written: dict[str, Path] = {}

    if "json" in active_formats:
        written["json"] = generate_json_report(result, out_dir / "report.json")
    if "markdown" in active_formats:
        written["markdown"] = generate_markdown_report(result, out_dir / "report.md")
    if "html" in active_formats:
        written["html"] = generate_html_report(result, out_dir / "report.html")
    if "sarif" in active_formats:
        written["sarif"] = generate_sarif_report(result, out_dir / "report.sarif")

    return written


__all__ = [
    "generate_html_report",
    "generate_json_report",
    "generate_markdown_content",
    "generate_markdown_report",
    "generate_sarif_report",
    "print_console_report",
    "write_all_reports",
]
