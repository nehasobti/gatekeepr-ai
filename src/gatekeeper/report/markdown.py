"""Markdown report generator for PR comments and artifacts."""

from __future__ import annotations

from pathlib import Path

from gatekeeper.models import AuditResult, Verdict


def generate_markdown_content(result: AuditResult) -> str:
    """Generate Markdown text for PR summary comment or report.md."""
    badge = (
        "🟢 **PASS**"
        if result.verdict == Verdict.PASS
        else "🟡 **SKIPPED**"
        if result.verdict == Verdict.SKIPPED
        else "🔴 **FAIL**"
    )

    lines: list[str] = [
        f"## Gatekeeper AI Quality Gate: {badge}",
        "",
        "<!-- gatekeeper-summary-marker -->",
        "",
        "### Summary",
        "",
        "| Critical | High | Medium | Low | Info | Total |",
        "| :---: | :---: | :---: | :---: | :---: | :---: |",
        f"| {result.summary.critical} | {result.summary.high} | {result.summary.medium} | {result.summary.low} | {result.summary.info} | {result.summary.total} |",
        "",
    ]

    if result.findings:
        lines.extend(
            [
                "### Findings",
                "",
                "| Severity | File:Line | Category | Issue | Suggested Fix |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for f in result.findings:
            loc = f"`{f.file}:{f.start_line}`"
            fix = f.suggested_fix.replace("\n", " ").strip()
            if len(fix) > 120:
                fix = fix[:117] + "..."
            lines.append(
                f"| **{f.severity.value.upper()}** | {loc} | `{f.category.value}` | **{f.title}**<br>{f.explanation} | {fix} |"
            )
        lines.append("")
    else:
        if result.verdict == Verdict.PASS:
            lines.extend(
                [
                    "No blocking issues found. Code changes meet all quality and security gates.",
                    "",
                ]
            )

    if result.metadata.skipped_files:
        lines.extend(
            [
                "### Unreviewed / Skipped Files",
                "",
                "<details><summary>Click to view skipped files</summary>",
                "",
            ]
        )
        for sf in result.metadata.skipped_files:
            lines.append(f"- `{sf}`")
        lines.extend(["", "</details>", ""])

    meta = result.metadata
    lines.extend(
        [
            "---",
            "### Run Details",
            f"- **Model**: `{meta.model}` | **Prompt Version**: `{meta.prompt_version}`",
            f"- **Tokens**: In `{meta.input_tokens}` | Out `{meta.output_tokens}` | Cached `{meta.cached_tokens}`",
            f"- **Estimated Cost**: `${meta.estimated_cost_usd:.4f}` | **Duration**: `{meta.duration_seconds:.2f}s`",
            "",
        ]
    )

    return "\n".join(lines)


def generate_markdown_report(result: AuditResult, output_path: str | Path) -> Path:
    """Write markdown report to disk."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = generate_markdown_content(result)
    path.write_text(content, encoding="utf-8")
    return path
