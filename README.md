# Gatekeeper AI

> **Plug-and-play AI quality gate for pull requests powered by Claude and static security scanners.**

Gatekeeper AI reviews only changed code in pull requests using Claude (with prompt caching and forced tool schemas) combined with static scanners (Semgrep, Bandit, Gitleaks, SonarQube). It applies team-configured thresholds and returns `PASS`, `FAIL`, or `ERROR` to block vulnerable code from reaching QA or production.

[![CI](https://github.com/gatekeeper-ai/gatekeeper-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/gatekeeper-ai/gatekeeper-ai/actions)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/release/python-3120/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## ⚡ 5-Minute Quick Start

### 1. GitHub Actions

Add `.github/workflows/gatekeeper.yml` to your repo:

```yaml
name: Gatekeeper AI
on:
  pull_request:
    branches: [qa, main]

permissions:
  contents: read
  pull-requests: write
  checks: write
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: gatekeeper-ai/gatekeeper-ai@v1
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GK_SLACK_WEBHOOK: ${{ secrets.GK_SLACK_WEBHOOK }}

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: gatekeeper-report
          path: gatekeeper-report/
```

Then require the **Gatekeeper AI** status check in your repository's Branch Protection settings.

---

### 2. Bitbucket Pipelines

Add the Gatekeeper Pipe to `bitbucket-pipelines.yml`:

```yaml
pipelines:
  pull-requests:
    '**':
      - step:
          name: Gatekeeper AI audit
          clone:
            depth: full
          script:
            - pipe: docker://gatekeeper-ai/gatekeeper-ai-pipe:1.0.0
              variables:
                ANTHROPIC_API_KEY: $ANTHROPIC_API_KEY
                BITBUCKET_ACCESS_TOKEN: $GK_BITBUCKET_TOKEN
                GK_TEAMS_WEBHOOK: $GK_TEAMS_WEBHOOK
          artifacts:
            - gatekeeper-report/**
```

Then enable merge checks in **Branch restrictions** ("No failed builds", "1 successful build", and Code Insights report).

---

## 🔍 How Gatekeeper Works

```text
PR Diff ──► Filter & Chunk ──► [ Claude Passes ] ──┬──► Merge & Dedupe ──► Gate Verdict (PASS/FAIL)
                           └──► [ Scanners + Triage ]─┘        │
                                                               └──► PR Comments, SARIF, Alerts
```

1. **Loads only changed code**: Enforces `max_files` (60) and `max_diff_lines` (3000). Context lines (20) are provided for understanding but never flagged.
2. **Pre-flight Secret Redaction**: Masks high-entropy secrets and CI environment variables with `[REDACTED:****]` before LLM transmission.
3. **Claude Passes**: Evaluates chunks concurrently for `security` and `quality`. System instructions utilize **prompt caching** (90% discount on input tokens).
4. **Static Scanners & LLM Triage**: Executes Semgrep, Bandit, Gitleaks, and SonarQube; triages false positives with Claude.
5. **Enforces Gates**: Compares findings against thresholds (`critical: 1`, `high: 1`, `medium: 10`). Returns exit code `1` on failure to block merges.

---

## 📊 Outputs & Reports

Every run outputs to `gatekeeper-report/`:
- **PR Summary Comment**: In-place updated comment with severity badges and top findings.
- **Inline Comments**: Precise line-level annotations on the pull request diff with remediation advice.
- **`report.html`**: Interactive, standalone HTML dashboard with category filters and code snippets.
- **`report.sarif`**: SARIF 2.1.0 standard report uploaded to GitHub Code Scanning.
- **`report.json`**: Machine-readable full audit telemetry.
- **Notifications**: Instant alerts to Slack, Microsoft Teams, and Email (SMTP TLS).

---

## 💻 Local CLI Usage

Install locally via `uv` or `pip`:

```bash
uv pip install gatekeeper-ai

# Initialize starter configuration
gatekeeper init

# Audit diff between two local branches
gatekeeper audit --base main --head feature/auth

# Dry run (estimate tokens without calling Claude)
gatekeeper audit --dry-run

# Rebuild HTML report from existing JSON
gatekeeper report --from gatekeeper-report/report.json --format html
```

---

## 📚 Documentation

Visit the full [Documentation Site](https://gatekeeper-ai.github.io/gatekeeper-ai/):
- [GitHub Actions Guide](docs/quickstart_github.md)
- [Bitbucket Pipelines Guide](docs/quickstart_bitbucket.md)
- [Configuration Reference](docs/configuration.md)
- [Rules & Thresholds](docs/rules.md)
- [Suppressions & Baselines](docs/suppressions.md)
- [Static Scanners & Triage](docs/scanners.md)
- [Notification Channels](docs/notifications.md)
- [Cost & Token Optimization](docs/costs.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Architecture Decisions](DECISIONS.md)
- [Changelog](CHANGELOG.md)

---

## 📄 License

MIT License. Copyright (c) 2026 Gatekeeper AI Authors.
