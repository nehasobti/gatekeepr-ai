# Changelog

All notable changes to Gatekeeper AI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-06

### Added
- **Phase 1: Core Engine**: Local audit CLI, Pydantic v2 schemas, diff parsing and filtering with unidiff, chunking, Claude client with forced schema, mock LLM, gate evaluation rules, and Markdown/HTML/JSON/SARIF reporting.
- **Phase 2: Bitbucket Cloud Integration**: Platform adapter with PR diff retrieval, in-place summary comment updates, inline diff comments, Code Insights report creation with bulk annotations, Bitbucket Pipe (`pipe/pipe.yml`), Dockerfile, and pipeline examples.
- **Phase 3: GitHub Actions Integration**: GitHub platform adapter, in-place summary updates, review comments, `Gatekeeper AI` check runs for branch protection, SARIF 2.1.0 code scanning upload, Docker action (`action.yml`), and workflow examples.
- **Phase 4: Notifications, Reports & Security**: Secret redaction engine (`src/gatekeeper/security/redactor.py`), chunk-level result caching in `.gatekeeper/cache`, Slack Block Kit webhooks, Microsoft Teams Adaptive Cards, SMTP TLS email notifications with HTML report attachment.
- **Phase 5: Static Scanners, Triage, Docs & Release**:
  - Semgrep runner with OWASP ruleset integration (`src/gatekeeper/scanners/semgrep.py`).
  - Bandit Python SAST runner (`src/gatekeeper/scanners/bandit.py`).
  - Gitleaks secret scanner with CLI and built-in rules fallback (`src/gatekeeper/scanners/gitleaks.py`).
  - SonarQube / SonarCloud REST API integration (`src/gatekeeper/scanners/sonarqube.py`).
  - LLM triage engine filtering static scanner false positives with Claude (`src/gatekeeper/engine/triage.py`).
  - Complete Material for MkDocs documentation site with quickstarts, architecture guides, and troubleshooting (`docs/`).
  - Full GitHub Actions CI and multi-target Release workflow (`.github/workflows/ci.yml` and `.github/workflows/release.yml`).
