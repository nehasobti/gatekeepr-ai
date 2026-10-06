"""Static analysis triage engine combining scanner findings with LLM verification."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from gatekeeper.models import Finding

if TYPE_CHECKING:
    from gatekeeper.llm.client import LLMClient
    from gatekeeper.llm.mock import MockLLMClient

logger = logging.getLogger("gatekeeper.engine.triage")


def extract_finding_context(finding: Finding, repo_root: Path, radius: int = 5) -> str:
    """Extract source code surrounding a finding's line range."""
    file_path = repo_root / finding.file
    if not file_path.is_file():
        return ""

    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return ""

    total_lines = len(lines)
    start_idx = max(0, finding.start_line - 1 - radius)
    end_idx = min(total_lines, finding.end_line + radius)

    snippet_lines: list[str] = []
    for i in range(start_idx, end_idx):
        line_num = i + 1
        marker = ">" if finding.start_line <= line_num <= finding.end_line else " "
        snippet_lines.append(f"{marker} {line_num:4d} | {lines[i]}")

    return "\n".join(snippet_lines)


def triage_scanner_findings(
    findings: list[Finding],
    repo_root: Path,
    llm: LLMClient | MockLLMClient,
) -> tuple[list[Finding], list[Finding]]:
    """Triage scanner findings using Claude to identify and filter out false positives.

    Returns:
        (confirmed_findings, dismissed_findings)
    """
    if not findings:
        return [], []

    snippets: dict[str, str] = {}
    for f in findings:
        snippets[f.id] = extract_finding_context(f, repo_root)

    try:
        confirmed = llm.triage_findings(findings, snippets)
        confirmed_ids = {f.id for f in confirmed}
        dismissed = [f for f in findings if f.id not in confirmed_ids]
        logger.info(
            f"LLM Triage evaluated {len(findings)} findings: {len(confirmed)} confirmed, {len(dismissed)} dismissed as false positives"
        )
        return confirmed, dismissed
    except Exception as e:
        logger.warning(f"Error during LLM triage: {e}. Retaining all scanner findings.")
        return findings, []
