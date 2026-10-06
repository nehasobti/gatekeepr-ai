# Security & Privacy

Gatekeeper AI is designed to protect your source code and API credentials by default.

---

## 1. Secrets Handling
- **No Secrets in Config**: All credentials (`ANTHROPIC_API_KEY`, `GITHUB_TOKEN`, `BITBUCKET_ACCESS_TOKEN`, webhook URLs) must be supplied via CI environment variables or secrets stores.
- **Pre-flight Secret Redaction**: Before sending code hunks to Claude, Gatekeeper scans the text using Gitleaks-compatible regexes and active CI environment variables. Any matching secret value is replaced with `[REDACTED:****]`.
- **Log Masking**: Output logs and reports never reveal secret values.

---

## 2. Least Privilege Permissions

### GitHub Actions
Gatekeeper only requires permissions to write PR comments, checks, and code scanning alerts:

```yaml
permissions:
  contents: read
  pull-requests: write
  checks: write
  security-events: write
```

### Bitbucket Cloud
Repository Access Tokens require only:
- `Pull requests: write` (for posting comments and Code Insights reports).

---

## 3. Untrusted / Forked Pull Requests
On GitHub, workflows should trigger on `pull_request` (never `pull_request_target`) to prevent untrusted forks from accessing repository secrets. Pull requests originating from public forks that cannot access repository secrets are gracefully skipped by default.

---

## 4. Prompt Injection Defense
- Source code in prompts is treated strictly as data, demarcated inside fenced blocks (````diff ... ````).
- System prompts explicitly direct Claude to disregard instructions contained within reviewed code.
- Claude's output is constrained to a rigid Pydantic JSON schema through forced tool calls (`submit_findings` and `submit_triage`). Prompt injections cannot alter the verdict or report structure.

---

## 5. Data Privacy & Claude Retention
- Only modified diff hunks and `context_lines` surrounding changed lines are sent to Anthropic's API.
- Files excluded in `gatekeeper.yml` (such as `.env`, credentials, large binaries) are never read or transmitted.
- For Anthropic API customers, commercial data privacy terms guarantee that customer data submitted through the API is not used to train models.
