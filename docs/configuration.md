# Configuration Reference

All behavior in Gatekeeper AI is controlled by `gatekeeper.yml` located in the root of the repository.

---

## Starter File Generation

You can generate a starter configuration file using the CLI:

```bash
# Generate default balanced configuration
gatekeeper init

# Generate strict preset
gatekeeper init --preset strict

# Generate lenient preset
gatekeeper init --preset lenient
```

Validate your configuration and environment credentials with:

```bash
gatekeeper validate-config
```

---

## Schema Reference

### `version`
- **Type**: `integer`
- **Default**: `1`
- **Description**: Schema version number.

---

### `model`
- `provider`: `string` (default: `"anthropic"`). LLM provider.
- `name`: `string` (default: `"claude-sonnet-latest"`). Anthropic model ID.
- `max_output_tokens`: `integer` (default: `4096`). Maximum tokens per response.
- `temperature`: `float` (default: `0.0`). Sampling temperature.

---

### `review`
- `passes`: `list[string]` (default: `["security", "quality"]`). Review passes to execute.
- `target_branches`: `list[string]` (default: `["qa", "main"]`). PRs targeting other branches are skipped (`exit 0`).
- `include`: `list[string]` (default: `["**/*"]`). Glob patterns of files to include in reviews.
- `exclude`: `list[string]` (default: `["**/*.lock", "**/dist/**", "**/vendor/**", "**/*.min.js", "**/migrations/**", "**/.venv/**"]`). Files to skip.
- `max_files`: `integer` (default: `60`). Maximum number of changed files reviewed in one PR.
- `max_diff_lines`: `integer` (default: `3000`). Maximum cumulative changed diff lines before truncation.
- `context_lines`: `integer` (default: `20`). Surrounding lines around changed hunks sent to Claude.
- `language_hints`: `string` (default: `"auto"`).
- `custom_rules`: `list[string]` (default: `[]`). Plain-English custom security and code quality rules enforced by Claude.

---

### `budget`
- `max_input_tokens_per_run`: `integer` (default: `200000`). Hard ceiling on total input tokens per audit.
- `on_budget_exceeded`: `"warn" | "fail" | "skip_remaining"` (default: `"warn"`). Action when token limit is hit.

---

### `scanners`
- `semgrep`: `{ enabled: bool, config: string }` (default: `{ enabled: true, config: "p/owasp-top-ten" }`).
- `bandit`: `{ enabled: bool | "auto" }` (default: `{ enabled: auto }`). Runs only if `.py` files changed.
- `gitleaks`: `{ enabled: bool }` (default: `{ enabled: true }`). Scans diff and files for hardcoded secrets.
- `sonarqube`: `{ enabled: bool, url_env: string, token_env: string, project_key: string }`.
- `triage_with_llm`: `bool` (default: `true`). Claude reviews scanner findings and filters false positives.

---

### `gate`
- `fail_on`: Thresholds triggering gate failure if count >= threshold:
  - `critical`: `integer` (default: `1`)
  - `high`: `integer` (default: `1`)
  - `medium`: `integer` (default: `10`)
  - `low`: `integer` (default: `999999`)
  - `info`: `integer` (default: `999999`)
- `min_confidence`: `"high" | "medium" | "low"` (default: `"medium"`). Findings below this confidence are ignored.
- `fail_on_scanner_error`: `bool` (default: `false`).
- `fail_on_llm_error`: `bool` (default: `true`). If Claude API is unavailable, fail safe with exit code `2`.

---

### `suppressions`
- `inline_marker`: `string` (default: `"gatekeeper-ignore"`). Comment marker for line suppressions.
- `baseline_file`: `string` (default: `".gatekeeper/baseline.json"`). Path to suppressed baseline file.

---

### `outputs`
- `pr_comment`: `"off" | "summary" | "summary_and_inline"` (default: `"summary_and_inline"`).
- `max_inline_comments`: `integer` (default: `25`).
- `formats`: `list[string]` (default: `["markdown", "html", "json", "sarif"]`).
- `output_dir`: `string` (default: `"gatekeeper-report"`).

---

### `notify`
- `on`: `list["fail" | "error" | "pass"]` (default: `["fail", "error"]`).
- `slack`: `{ webhook_env: "GK_SLACK_WEBHOOK" }`.
- `teams`: `{ webhook_env: "GK_TEAMS_WEBHOOK" }`.
- `email`:
  - `smtp_host_env`: `"GK_SMTP_HOST"`
  - `smtp_user_env`: `"GK_SMTP_USER"`
  - `smtp_password_env`: `"GK_SMTP_PASSWORD"`
  - `from`: `"gatekeeper@example.com"`
  - `to`: `["qa-lead@example.com"]`

---

## Presets Comparison

| Feature | Strict | Balanced (Default) | Lenient |
| --- | --- | --- | --- |
| Critical Threshold | 1 | 1 | 1 |
| High Threshold | 1 | 1 | 999 (disabled) |
| Medium Threshold | 5 | 10 | 999 (disabled) |
| Budget Exceeded | `fail` | `warn` | `warn` |
| Fail on LLM Error | `true` | `true` | `false` |
| Scanners | All + Triage | All + Triage | Gitleaks Only |
