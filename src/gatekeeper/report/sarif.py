"""SARIF 2.1.0 report generator for GitHub code scanning integration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from gatekeeper.models import AuditResult, Severity


def severity_to_sarif_level(sev: Severity) -> str:
    """Map Gatekeeper severity to SARIF level."""
    if sev in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    elif sev == Severity.MEDIUM:
        return "warning"
    elif sev == Severity.LOW:
        return "note"
    return "none"


def generate_sarif_dict(result: AuditResult) -> dict[str, Any]:
    """Generate SARIF 2.1.0 schema dictionary from AuditResult."""
    rules_map: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []

    for f in result.findings:
        rule_id = f"GK-{f.category.value.upper()}"
        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": f.category.value.replace("_", " ").title(),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.explanation},
                "defaultConfiguration": {"level": severity_to_sarif_level(f.severity)},
                "properties": {
                    "precision": f.confidence.value,
                    "tags": ["security", f.category.value],
                },
            }
            if f.cwe:
                rules_map[rule_id]["properties"]["tags"].append(f.cwe)

        res_item: dict[str, Any] = {
            "ruleId": rule_id,
            "level": severity_to_sarif_level(f.severity),
            "message": {"text": f"{f.title}: {f.explanation}\nSuggested Fix: {f.suggested_fix}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": f.start_line,
                            "endLine": f.end_line,
                        },
                    }
                }
            ],
            "properties": {
                "findingId": f.id,
                "confidence": f.confidence.value,
                "sources": f.source,
            },
        }
        sarif_results.append(res_item)

    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Gatekeeper AI",
                        "version": result.metadata.tool_version,
                        "informationUri": "https://github.com/tychon/gatekeeper-ai",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return sarif


def generate_sarif_report(result: AuditResult, output_path: str | Path) -> Path:
    """Write SARIF 2.1.0 report to disk."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = generate_sarif_dict(result)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path
