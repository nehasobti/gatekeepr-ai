# Gatekeeper AI

> **Plug-and-play AI quality gate for pull requests powered by Claude and static security scanners.**

Gatekeeper AI reviews only changed code in pull requests using Claude (with prompt caching and forced tool-use schema) combined with optional static scanners (Semgrep, Bandit, Gitleaks, SonarQube). It applies team-configured thresholds and returns `PASS`, `FAIL`, or `ERROR` to block vulnerable code from reaching QA or production.

```
       Pull Request Diff
               │
               ▼
   ┌───────────────────────┐
   │ 1. Filter & Chunk     │
   └───────────┬───────────┘
               │
        ┌──────┴──────┐
        ▼             ▼
┌──────────────┐ ┌──────────────────────┐
│ Static SAST  │ │ Claude Review Passes │
│ (Semgrep,    │ │ (Security & Quality, │
│ Bandit, etc) │ │  Prompt Caching)     │
└──────┬───────┘ └──────────┬───────────┘
       │                    │
       ▼                    │
┌──────────────┐            │
│  LLM Triage  │            │
└──────┬───────┘            │
       │                    │
       └──────┬─────────────┘
              ▼
   ┌───────────────────────┐
   │ Merge, Dedupe,        │
   │ Suppressions & Gate   │
   └──────────┬────────────┘
              ▼
         PASS or FAIL
   (PR comments, Check Runs,
    SARIF, Notifications)
```

---

## Key Features

- **Single Pipeline Snippet**: Add one YAML snippet to GitHub Actions or Bitbucket Pipelines and configure your Anthropic API key.
- **Zero Hallucinated Lines**: Tool-use validation drops any finding whose line numbers fall outside the actual git diff.
- **Prompt Caching & Result Caching**: Saves up to 90% in token costs on Claude API calls and instantly returns cached results for unchanged PR hunks.
- **Pre-flight Secret Redaction**: Automatically scans and masks AWS keys, GitHub tokens, Slack secrets, and environment variable values before sending snippets to LLMs.
- **Hybrid Scanner Orchestration**: Merges static findings from Semgrep, Bandit, Gitleaks, and SonarQube, using Claude to triage false positives.
- **First-Class Platform Integrations**:
  - **GitHub Actions**: In-place summary comment updates, PR review with line comments, status check runs, and direct SARIF 2.1.0 code scanning upload.
  - **Bitbucket Pipelines**: In-place summary comments, inline discussions, and native Code Insights reports with annotations.
- **Multi-Channel Alerts**: Rich Slack Block Kit, Microsoft Teams Adaptive Cards, and SMTP email notifications with attached standalone HTML reports.

---

## Quick Navigation

- [GitHub Actions Quick Start](quickstart_github.md)
- [Bitbucket Pipelines Quick Start](quickstart_bitbucket.md)
- [Configuration Reference](configuration.md)
- [Severity & Gate Rules](rules.md)
- [Suppressions & Baseline](suppressions.md)
- [Static Scanners & LLM Triage](scanners.md)
- [Notifications Setup](notifications.md)
- [Reports & Formats](reports.md)
- [Security & Privacy](security.md)
- [Cost & Budget Guide](costs.md)
- [Custom Rules](custom_rules.md)
- [Troubleshooting](troubleshooting.md)
