"""Notifications package for Gatekeeper AI."""

from __future__ import annotations

import logging
from pathlib import Path

from gatekeeper.config import NotifyConfig
from gatekeeper.models import AuditResult, Verdict
from gatekeeper.notify.email import send_email_notification
from gatekeeper.notify.slack import send_slack_notification
from gatekeeper.notify.teams import send_teams_notification

logger = logging.getLogger("gatekeeper.notify")


def dispatch_notifications(
    result: AuditResult,
    config: NotifyConfig,
    html_report_path: Path | str | None = None,
) -> dict[str, bool]:
    """Dispatch notifications to configured channels (Slack, Teams, Email) if conditions are met."""
    status_key = (
        "fail"
        if result.verdict == Verdict.FAIL
        else "error"
        if result.verdict == Verdict.ERROR
        else "pass"
    )
    results: dict[str, bool] = {"slack": False, "teams": False, "email": False}

    if status_key not in config.on:
        return results

    # 1. Slack
    try:
        results["slack"] = send_slack_notification(result, config.slack)
    except Exception as e:
        logger.warning(f"Failed to send Slack notification: {e}")

    # 2. Teams
    try:
        results["teams"] = send_teams_notification(result, config.teams)
    except Exception as e:
        logger.warning(f"Failed to send Teams notification: {e}")

    # 3. Email
    try:
        results["email"] = send_email_notification(result, config.email, html_report_path)
    except Exception as e:
        logger.warning(f"Failed to send email notification: {e}")

    return results


__all__ = [
    "dispatch_notifications",
    "send_email_notification",
    "send_slack_notification",
    "send_teams_notification",
]
