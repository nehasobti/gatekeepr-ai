"""Slack incoming webhook notification adapter."""

from __future__ import annotations

import os
from typing import Any

import httpx

from gatekeeper.config import SlackConfig
from gatekeeper.models import AuditResult, Verdict


def send_slack_notification(
    result: AuditResult,
    config: SlackConfig,
    webhook_url: str | None = None,
    client: httpx.Client | None = None,
) -> bool:
    """Send an audit result notification to Slack via incoming webhook."""
    url = webhook_url or os.environ.get(config.webhook_env)
    if not url:
        return False

    color = (
        "#10b981"
        if result.verdict == Verdict.PASS
        else "#f59e0b"
        if result.verdict == Verdict.SKIPPED
        else "#ef4444"
    )
    status_icon = (
        "🟢 PASS"
        if result.verdict == Verdict.PASS
        else "🟡 SKIPPED"
        if result.verdict == Verdict.SKIPPED
        else "🔴 FAIL"
    )

    top_findings_text = ""
    if result.findings:
        top_5 = result.findings[:5]
        lines = []
        for f in top_5:
            lines.append(f"• *[{f.severity.value.upper()}]* `{f.file}:{f.start_line}` - {f.title}")
        top_findings_text = "\n".join(lines)
        if len(result.findings) > 5:
            top_findings_text += f"\n_...and {len(result.findings) - 5} more findings_"
    else:
        top_findings_text = "_No blocking issues detected._"

    meta = result.metadata
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"Gatekeeper AI Quality Gate: {status_icon}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Verdict:*\n{result.verdict.value}"},
                {"type": "mrkdwn", "text": f"*Total Findings:*\n{result.summary.total}"},
                {
                    "type": "mrkdwn",
                    "text": f"*Severity:*\n🔴 {result.summary.critical} Crit | 🟠 {result.summary.high} High | 🟡 {result.summary.medium} Med",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Cost / Tokens:*\n${meta.estimated_cost_usd:.4f} ({meta.input_tokens + meta.output_tokens} tok)",
                },
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Top Findings:*\n{top_findings_text}",
            },
        },
    ]

    payload = {
        "text": f"Gatekeeper AI: {result.verdict.value} ({result.summary.total} issues)",
        "attachments": [
            {
                "color": color,
                "blocks": blocks,
            }
        ],
    }

    http_client = client or httpx.Client(timeout=10.0)
    resp = http_client.post(url, json=payload)
    return resp.status_code == 200
