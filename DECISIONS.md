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
