"""Suppression filtering for inline markers and baseline fingerprints."""

from __future__ import annotations

import json
import re
from pathlib import Path

from gatekeeper.config import SuppressionsConfig
from gatekeeper.models import Finding


def load_baseline_fingerprints(baseline_path: str | Path) -> set[str]:
    """Load suppressed finding IDs from baseline JSON file."""
    path = Path(baseline_path)
    if not path.exists():
        return set()

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                # list of finding IDs or objects
                return {item["id"] if isinstance(item, dict) else str(item) for item in data}
            elif isinstance(data, dict):
                findings = data.get("findings", [])
                return {item["id"] if isinstance(item, dict) else str(item) for item in findings}
    except Exception:
        return set()
    return set()


def check_inline_suppression(
    file_path: str,
    line_number: int,
    marker: str = "gatekeeper-ignore",
    repo_root: Path | None = None,
) -> tuple[bool, str]:
    """Check if the given line (or immediately preceding line) contains an inline suppression with a reason."""
    root = repo_root or Path.cwd()
    target = root / file_path
    if not target.exists() or not target.is_file():
        return False, ""

    try:
        with open(target, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        # Check line_number (1-indexed) and line_number - 1
        indices_to_check = [line_number - 1]
        if line_number - 2 >= 0:
            indices_to_check.append(line_number - 2)

        pattern = re.compile(rf"{re.escape(marker)}:\s*(.+)$", re.IGNORECASE)
        for idx in indices_to_check:
            if 0 <= idx < len(lines):
                line_content = lines[idx]
                match = pattern.search(line_content)
                if match:
                    reason = match.group(1).strip().rstrip("*/").strip()
                    if reason:
                        return True, reason
    except Exception:
        return False, ""

    return False, ""


def apply_suppressions(
    findings: list[Finding],
    suppressions_config: SuppressionsConfig,
    repo_root: Path | None = None,
) -> tuple[list[Finding], list[tuple[Finding, str]]]:
    """Filter out suppressed findings, returning active findings and dropped findings with reasons."""
    baseline_ids = load_baseline_fingerprints(suppressions_config.baseline_file)
    active: list[Finding] = []
    dropped: list[tuple[Finding, str]] = []

    for f in findings:
        if f.id in baseline_ids:
            dropped.append((f, "suppressed by baseline"))
            continue

        is_suppressed, reason = check_inline_suppression(
            file_path=f.file,
            line_number=f.start_line,
            marker=suppressions_config.inline_marker,
            repo_root=repo_root,
        )
        if is_suppressed:
            dropped.append((f, f"inline suppression: {reason}"))
            continue

        active.append(f)

    return active, dropped
