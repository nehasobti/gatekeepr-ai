# Static Scanners & LLM Triage

Gatekeeper AI combines semantic LLM reasoning with fast, deterministic static analysis tools.

---

## Supported Scanners

| Scanner | Language / Scope | Configuration |
| --- | --- | --- |
| **Semgrep** | Polyglot (Python, JS, TS, Go, Java, etc.) | `scanners.semgrep.config: "p/owasp-top-ten"` |
| **Bandit** | Python AST security issues | `scanners.bandit.enabled: "auto"` |
| **Gitleaks** | Hardcoded secrets, API tokens, private keys | `scanners.gitleaks.enabled: true` |
| **SonarQube** | SonarQube / SonarCloud Web API issues | `scanners.sonarqube.enabled: true` |

---

## 1. Semgrep Integration

Runs Semgrep rulesets on changed files:

```yaml
scanners:
  semgrep:
    enabled: true
    config: "p/owasp-top-ten"
```

If Semgrep CLI is not installed, it logs a warning and gracefully continues without failing the build (unless `fail_on_scanner_error: true`).

---

## 2. Bandit Integration

When set to `auto`, Bandit only runs if Python files (`*.py`) were added or modified in the pull request:

```yaml
scanners:
  bandit:
    enabled: auto
```

Flags insecure deserialization (`B301`), hardcoded passwords (`B105`), weak crypto (`B303`/`B324`), and SQL injection (`B608`).

---

## 3. Gitleaks Integration

Scans changed diff hunks and files for sensitive credentials:

```yaml
scanners:
  gitleaks:
    enabled: true
```

Detects:
- AWS Access Keys (`AKIA...`)
- GitHub Personal Access Tokens (`ghp_...`)
- Slack tokens & webhooks
- Private cryptographic keys (`BEGIN PRIVATE KEY`)
- High-entropy API tokens

---

## 4. SonarQube & SonarCloud

Queries existing SonarQube or SonarCloud projects via the REST API:

```yaml
scanners:
  sonarqube:
    enabled: true
    url_env: SONAR_HOST_URL
    token_env: SONAR_TOKEN
    project_key: "my-organization_my-repo"
```

Fetches unresolved issues for the PR, maps SonarQube severities (`BLOCKER`, `CRITICAL`, `MAJOR`), and attributes findings to `source: ["sonarqube"]`.

---

## 5. LLM Triage Engine

Static analyzers frequently flag false positives on sanitized or safe code paths. When `scanners.triage_with_llm: true` is enabled:

1. Static scanner findings are extracted along with 10 lines of surrounding code context.
2. The code snippet is sent to Claude via prompt template `triage.md` using the `submit_triage` forced tool call.
3. Claude analyzes whether the finding is a **True Positive** or **False Positive**.
4. Dismissed false positives are logged and filtered out before gate evaluation, preventing unnecessary pipeline blocks.
