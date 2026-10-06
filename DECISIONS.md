# Architecture & Design Decisions

This document tracks decisions made during the implementation of Gatekeeper AI according to the technical specification.

## Decision Log

### 1. Build and Package Management
- **Date**: 2026-10-06
- **Decision**: Use `hatchling` as build backend with `uv` for virtual environment and dependency management.
- **Rationale**: Specified in tech spec for fast, reproducible Python 3.12 builds.

### 2. LLM Tool-Use Format for Findings
- **Date**: 2026-10-06
- **Decision**: Claude's output schema is enforced via a forced tool call (`submit_findings`) with a strict JSON schema mapped from Pydantic `Finding` models.
- **Rationale**: Eliminates markdown parsing fragility and ensures schema conformity.

### 3. Local Git Diff Execution
- **Date**: 2026-10-06
- **Decision**: For local mode, run `git diff --unified=N base...head` or `base head` using subprocess to generate standard unified diffs parsed by `unidiff`.
- **Rationale**: Works reliably across Windows PowerShell and Linux without extra external git dependencies.

### 4. Bitbucket Cloud Code Insights & Merge Blocking
- **Date**: 2026-10-06
- **Decision**: Code Insights reports use report key `gatekeeper-ai` with `SECURITY` report type and bulk annotations (up to 100 per batch). Summary comments detect existing comments using `<!-- gatekeeper-summary-marker -->` and update via `PUT`.
- **Rationale**: Standard Bitbucket Cloud REST API 2.0 pattern allowing native integration with Bitbucket branch restrictions.

### 5. GitHub Integration, Check Runs, and SARIF Upload
- **Date**: 2026-10-06
- **Decision**: GitHub platform posts PR reviews (`event: COMMENT`) with line-level findings, creates a check run named `Gatekeeper AI` with conclusion `success` or `failure` for branch protection, and uploads gzipped, base64-encoded SARIF 2.1.0 payloads directly to `/repos/{owner}/{repo}/code-scanning/sarifs`.
- **Rationale**: Native GitHub Actions integration enabling required status checks and security tab code scanning alerts.

### 6. Pre-flight Secret Redaction
- **Date**: 2026-10-06
- **Decision**: Implement regex-based and environment-variable-value matching before sending diff snippets or logs to LLMs or external systems. Matching values are replaced with `[REDACTED:****]`.
- **Rationale**: Prevents accidental leakage of private keys, AWS/GitHub/Slack tokens, passwords, and CI environment secrets to LLM providers or log outputs.

### 7. LLM Chunk Result Caching
- **Date**: 2026-10-06
- **Decision**: File-based chunk review caching using SHA-256 hashes of chunk content, review pass name, prompt version, model name, and custom rules into `.gatekeeper/cache`.
- **Rationale**: Avoids redundant LLM queries and token cost when re-running checks on unchanged code or unmodified PR chunks.

### 8. Multi-channel Notifications
- **Date**: 2026-10-06
- **Decision**: Implement Slack Block Kit webhooks, Microsoft Teams Adaptive Cards webhooks, and standard SMTP TLS email with attached HTML reports. Conditioned on status matching `notify.on` (`fail`, `error`, `pass`).
- **Rationale**: Provides actionable, cross-team security status updates to Slack channels, Microsoft Teams rooms, and security lead inboxes upon audit completion.
