"""SMTP email notification adapter with attached HTML report."""

from __future__ import annotations

import os
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

from gatekeeper.config import EmailConfig
from gatekeeper.models import AuditResult
from gatekeeper.report.html import generate_html_content


def send_email_notification(
    result: AuditResult,
    config: EmailConfig,
    html_report_path: Path | str | None = None,
    smtp_client: smtplib.SMTP | None = None,
) -> bool:
    """Send an audit result notification via SMTP with an HTML report attachment."""
    host = os.environ.get(config.smtp_host_env)
    if not host or not config.to:
        return False

    username = os.environ.get(config.smtp_user_env, "")
    password = os.environ.get(config.smtp_password_env, "")

    msg = MIMEMultipart("mixed")
    msg["Subject"] = (
        f"Gatekeeper AI Quality Gate: [{result.verdict.value}] - {result.summary.total} findings"
    )
    msg["From"] = config.from_address
    msg["To"] = ", ".join(config.to)

    # HTML body
    body_text = (
        f"<h2>Gatekeeper AI Quality Gate: {result.verdict.value}</h2>\n"
        f"<p>Critical: <b>{result.summary.critical}</b> | "
        f"High: <b>{result.summary.high}</b> | "
        f"Medium: <b>{result.summary.medium}</b> | "
        f"Low: <b>{result.summary.low}</b> | "
        f"Total: <b>{result.summary.total}</b></p>\n"
        f"<p>Full interactive report is attached.</p>"
    )
    msg.attach(MIMEText(body_text, "html", "utf-8"))

    # Attachment
    if html_report_path and Path(html_report_path).exists():
        html_bytes = Path(html_report_path).read_bytes()
    else:
        html_bytes = generate_html_content(result).encode("utf-8")

    part = MIMEApplication(html_bytes, Name="gatekeeper-report.html")
    part["Content-Disposition"] = 'attachment; filename="gatekeeper-report.html"'
    msg.attach(part)

    try:
        if smtp_client is not None:
            smtp_client.send_message(msg)
            return True

        # Default port 587 with STARTTLS
        with smtplib.SMTP(host, 587, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            if username and password:
                server.login(username, password)
            server.send_message(msg)
        return True
    except Exception:
        return False
