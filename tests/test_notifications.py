"""Unit tests for notification adapters (Slack, Teams, Email) and dispatcher."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
import respx

from gatekeeper.config import EmailConfig, NotifyConfig, SlackConfig, TeamsConfig
from gatekeeper.models import (
    AuditMetadata,
    AuditResult,
    AuditSummary,
    Category,
    Confidence,
    Finding,
    Severity,
    Verdict,
)
from gatekeeper.notify import (
    dispatch_notifications,
    send_email_notification,
    send_slack_notification,
    send_teams_notification,
)


@pytest.fixture
def sample_failed_result() -> AuditResult:
    f1 = Finding.create(
        file="src/app.py",
        start_line=12,
        end_line=12,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        category=Category.INJECTION,
        title="SQL Injection",
        explanation="Direct concatenation",
        suggested_fix="Param query",
    )
    f2 = Finding.create(
        file="src/auth.py",
        start_line=25,
        end_line=25,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.AUTH,
        title="Missing Auth",
        explanation="Unprotected admin endpoint",
        suggested_fix="Add login_required",
    )
    findings = [f1, f2]
    return AuditResult(
        verdict=Verdict.FAIL,
        findings=findings,
        summary=AuditSummary.from_findings(findings),
        metadata=AuditMetadata(
            tool_version="0.1.0",
            prompt_version="1.0.0",
            model="claude-sonnet-latest",
            duration_seconds=1.5,
            input_tokens=500,
            output_tokens=150,
            estimated_cost_usd=0.0035,
        ),
    )


@respx.mock
def test_send_slack_notification(sample_failed_result: AuditResult) -> None:
    webhook_url = "https://hooks.slack.com/services/T00/B00/X00"
    route = respx.post(webhook_url).mock(return_value=httpx.Response(200, text="ok"))

    cfg = SlackConfig()
    success = send_slack_notification(sample_failed_result, cfg, webhook_url=webhook_url)

    assert success is True
    assert route.called
    data = json.loads(route.calls.last.request.read().decode("utf-8"))
    assert "FAIL" in data["text"]
    assert "SQL Injection" in str(data["attachments"])


@respx.mock
def test_send_teams_notification(sample_failed_result: AuditResult) -> None:
    webhook_url = "https://custom.webhook.office.com/webhookb2/teams-test"
    route = respx.post(webhook_url).mock(return_value=httpx.Response(200, text="ok"))

    cfg = TeamsConfig()
    success = send_teams_notification(sample_failed_result, cfg, webhook_url=webhook_url)

    assert success is True
    assert route.called
    data = json.loads(route.calls.last.request.read().decode("utf-8"))
    card = data["attachments"][0]["content"]
    assert card["type"] == "AdaptiveCard"
    card_text = json.dumps(card)
    assert "FAIL" in card_text
    assert "SQL Injection" in card_text


def test_send_email_notification(sample_failed_result: AuditResult, tmp_path: Path) -> None:
    html_file = tmp_path / "report.html"
    html_file.write_text("<html>Report</html>", encoding="utf-8")

    cfg = EmailConfig(
        smtp_host_env="TEST_SMTP_HOST",
        smtp_user_env="TEST_SMTP_USER",
        smtp_password_env="TEST_SMTP_PASS",
        from_address="gatekeeper@example.com",
        to=["qa@example.com"],
    )

    mock_smtp = MagicMock()
    success = send_email_notification(
        sample_failed_result,
        cfg,
        html_report_path=html_file,
        smtp_client=mock_smtp,
    )

    # Missing env host
    assert success is False

    # With host env set
    import os

    os.environ["TEST_SMTP_HOST"] = "smtp.example.com"
    success2 = send_email_notification(
        sample_failed_result,
        cfg,
        html_report_path=html_file,
        smtp_client=mock_smtp,
    )
    assert success2 is True
    assert mock_smtp.send_message.called


@respx.mock
def test_dispatch_notifications_all_three(
    sample_failed_result: AuditResult, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    slack_url = "https://hooks.slack.com/services/T00/B00/X00"
    teams_url = "https://custom.webhook.office.com/teams"
    respx.post(slack_url).mock(return_value=httpx.Response(200, text="ok"))
    respx.post(teams_url).mock(return_value=httpx.Response(200, text="ok"))

    monkeypatch.setenv("GK_SLACK_WEBHOOK", slack_url)
    monkeypatch.setenv("GK_TEAMS_WEBHOOK", teams_url)
    monkeypatch.setenv("GK_SMTP_HOST", "smtp.example.com")

    notify_cfg = NotifyConfig()
    notify_cfg.on = ["fail", "error"]

    mock_smtp = MagicMock()
    with monkeypatch.context() as m:
        m.setattr("smtplib.SMTP", MagicMock(return_value=mock_smtp))
        statuses = dispatch_notifications(
            sample_failed_result, notify_cfg, html_report_path=tmp_path / "report.html"
        )
        assert statuses["slack"] is True
        assert statuses["teams"] is True
