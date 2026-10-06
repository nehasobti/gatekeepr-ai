"""Microsoft Teams Workflows Adaptive Card notification adapter."""

from __future__ import annotations

import os
from typing import Any

import httpx

from gatekeeper.config import TeamsConfig
from gatekeeper.models import AuditResult, Verdict


def send_teams_notification(
    result: AuditResult,
    config: TeamsConfig,
    webhook_url: str | None = None,
    client: httpx.Client | None = None,
) -> bool:
    """Send an audit result notification to Microsoft Teams via Adaptive Card webhook."""
    url = webhook_url or os.environ.get(config.webhook_env)
    if not url:
        return False

    status_color = (
        "Good"
        if result.verdict == Verdict.PASS
        else "Warning"
        if result.verdict == Verdict.SKIPPED
        else "Attention"
    )
    status_icon = (
        "🟢 PASS"
        if result.verdict == Verdict.PASS
        else "🟡 SKIPPED"
        if result.verdict == Verdict.SKIPPED
        else "🔴 FAIL"
    )

    meta = result.metadata

    findings_items: list[dict[str, Any]] = []
    if result.findings:
        for f in result.findings[:5]:
            findings_items.append(
                {
                    "type": "TextBlock",
                    "text": f"- **[{f.severity.value.upper()}]** `{f.file}:{f.start_line}`: {f.title}",
                    "wrap": True,
                    "spacing": "Small",
                }
            )
        if len(result.findings) > 5:
            findings_items.append(
                {
                    "type": "TextBlock",
                    "text": f"*...plus {len(result.findings) - 5} additional findings*",
                    "isSubtle": True,
                    "spacing": "Small",
                }
            )
    else:
        findings_items.append(
            {
                "type": "TextBlock",
                "text": "No blocking issues detected.",
                "isSubtle": True,
            }
        )

    card_body: list[dict[str, Any]] = [
        {
            "type": "TextBlock",
            "size": "Large",
            "weight": "Bolder",
            "color": status_color,
            "text": f"Gatekeeper AI Quality Gate: {status_icon}",
        },
        {
            "type": "FactSet",
            "facts": [
                {"title": "Verdict", "value": result.verdict.value},
                {"title": "Total Issues", "value": str(result.summary.total)},
                {
                    "title": "Severity",
                    "value": f"Critical: {result.summary.critical} | High: {result.summary.high} | Medium: {result.summary.medium}",
                },
                {"title": "Cost", "value": f"${meta.estimated_cost_usd:.4f}"},
                {"title": "Model", "value": meta.model},
            ],
        },
        {
            "type": "TextBlock",
            "text": "Top Findings",
            "weight": "Bolder",
            "separator": True,
            "spacing": "Medium",
        },
        *findings_items,
    ]

    payload: dict[str, Any] = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": card_body,
                },
            }
        ],
    }

    http_client = client or httpx.Client(timeout=10.0)
    resp = http_client.post(url, json=payload)
    return resp.status_code in (200, 202)
