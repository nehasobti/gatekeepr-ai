# Notifications

Gatekeeper AI sends instant alerts when a quality gate audit completes with `FAIL` or `ERROR` (or optionally `PASS`).

---

## Configuration

In `gatekeeper.yml`:

```yaml
notify:
  on: [fail, error]
  slack:
    webhook_env: GK_SLACK_WEBHOOK
  teams:
    webhook_env: GK_TEAMS_WEBHOOK
  email:
    smtp_host_env: GK_SMTP_HOST
    smtp_user_env: GK_SMTP_USER
    smtp_password_env: GK_SMTP_PASSWORD
    from: gatekeeper@example.com
    to: [qa-lead@example.com, security@example.com]
```

---

## 1. Slack Webhooks

Uses Slack Block Kit to render formatted audit summaries:

- **Environment Variable**: `GK_SLACK_WEBHOOK`
- **Payload Features**:
  - Color-coded verdict header (`FAIL: Quality Gate Blocked`).
  - Breakdown table of findings by severity.
  - Top 5 critical issues with file paths and line numbers.
  - Context fields: target branch, commit SHA, PR ID, and tokens used.

---

## 2. Microsoft Teams Webhooks

Uses Adaptive Cards v1.4 compatible with Microsoft Teams Workflows (Power Automate):

- **Environment Variable**: `GK_TEAMS_WEBHOOK`
- **Card Elements**:
  - `TextBlock` title with color styling (`attention` on failure, `good` on pass).
  - FactSet with commit, branch, and failure counts.
  - Formatted findings list with explanations and remediation suggestions.

---

## 3. Email (SMTP TLS)

Sends notifications with the standalone HTML report attached:

- **Environment Variables**:
  - `GK_SMTP_HOST`: e.g. `smtp.gmail.com` or `email-smtp.us-east-1.amazonaws.com`
  - `GK_SMTP_USER`: SMTP username
  - `GK_SMTP_PASSWORD`: SMTP password
- **Behavior**:
  - Connects using secure TLS on port 587 (or port 25/465).
  - Composes multipart email with text summary in body.
  - Attaches `gatekeeper-report/report.html` for direct offline viewing in browsers.
