# Changelog

All notable changes to Gatekeeper AI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Phase 1: Core engine (local audit, config validation, diff loading and filtering, chunking, Claude client with forced schema, mock LLM, gate rules, Markdown/JSON/Console reporting).
- Phase 2: Bitbucket Cloud integration (platform adapter, pull request diff loading, summary comment creation and in-place updates, inline comments, Code Insights report with annotations, Bitbucket Pipe definition, Dockerfile, pipeline example, branch-restrictions guide).
- Phase 3: GitHub integration (platform adapter, pull request diff loading, summary comment update in-place, PR review with inline comments, check run creation for branch protection, SARIF 2.1.0 code scanning upload, Docker action `action.yml`, workflow example, branch-protection guide).
- Phase 4: Notifications, Reports & Security:
  - Secret redaction engine (`src/gatekeeper/security/redactor.py`) automatically masking API keys, private keys, JWTs, AWS credentials, and environment secret values before LLM processing.
  - Chunk-level result caching (`src/gatekeeper/llm/cache.py`) in `.gatekeeper/cache` using SHA-256 keys to avoid re-reviewing unchanged code chunks.
  - Slack Block Kit notifications (`src/gatekeeper/notify/slack.py`) via webhook.
  - Microsoft Teams Adaptive Card notifications (`src/gatekeeper/notify/teams.py`) via webhook.
  - Email notification sender (`src/gatekeeper/notify/email.py`) via SMTP TLS with attached HTML report.
  - Automated notification dispatcher integrated into the audit engine (`src/gatekeeper/engine/audit.py`).
