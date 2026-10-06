"""JSON report generator writing machine-readable AuditResult."""

from __future__ import annotations

from pathlib import Path

from gatekeeper.models import AuditResult


def generate_json_report(result: AuditResult, output_path: str | Path) -> Path:
    """Serialize AuditResult to JSON file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    json_str = result.model_dump_json(indent=2)
    path.write_text(json_str, encoding="utf-8")
    return path
