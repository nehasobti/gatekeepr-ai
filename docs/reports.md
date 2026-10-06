# Reports & Formats

Gatekeeper AI generates structured audit reports in multiple formats under `output_dir` (default: `gatekeeper-report/`).

---

## Generated Report Artifacts

| File | Format | Primary Use Case |
| --- | --- | --- |
| `report.html` | Self-contained HTML | Offline inspection, downloadable pipeline artifact, email attachment |
| `report.md` | GitHub Flavored Markdown | PR conversation summary, release notes, CI logs |
| `report.json` | JSON Schema v1.0 | Programmatic parsing, CI dashboards, telemetry |
| `report.sarif` | SARIF 2.1.0 | GitHub Code Scanning alerts under the Security tab |
| Console | Rich Terminal Output | CI runner log output |

---

## 1. HTML Report (`report.html`)
A standalone single-page application built with embedded CSS and modern design:
- Interactive filters for severity (`Critical`, `High`, `Medium`, `Low`, `Info`) and category (`Injection`, `Secrets`, etc.).
- Expandable finding cards showing the exact source code snippet and the suggested fix.
- Metadata drawer with tool version, prompt version, model ID, execution duration, tokens, and estimated cost in USD.

---

## 2. SARIF Report (`report.sarif`)
Complies strictly with the **Static Analysis Results Interchange Format (SARIF) 2.1.0** standard:
- Validated against GitHub Code Scanning specifications.
- Maps `Finding` models to SARIF `rules` and `results`.
- Uploaded automatically by Gatekeeper's GitHub Action adapter to `/repos/{owner}/{repo}/code-scanning/sarifs`.

---

## 3. JSON Report (`report.json`)
The complete `AuditResult` serialized into machine-readable JSON:

```json
{
  "verdict": "FAIL",
  "summary": {
    "critical": 1,
    "high": 1,
    "medium": 0,
    "low": 0,
    "info": 0,
    "total": 2
  },
  "findings": [
    {
      "id": "e3b0c44298fc1c14",
      "file": "src/app.py",
      "start_line": 15,
      "end_line": 15,
      "severity": "critical",
      "confidence": "high",
      "category": "injection",
      "owasp": "A03:2021 Injection",
      "cwe": "CWE-89",
      "title": "SQL Injection via string concatenation",
      "explanation": "Untrusted user input concatenated directly into database query.",
      "suggested_fix": "Use parameterized queries.",
      "source": ["claude", "semgrep"]
    }
  ],
  "metadata": {
    "tool_version": "0.1.0",
    "prompt_version": "1.0.0",
    "model": "claude-sonnet-latest",
    "config_hash": "a1b2c3d4e5f67890",
    "pr_id": "42",
    "duration_seconds": 3.82,
    "input_tokens": 1250,
    "output_tokens": 340,
    "cached_tokens": 800,
    "estimated_cost_usd": 0.0062
  }
}
```

---

## Rebuilding Reports
You can re-render HTML or Markdown reports from an existing `report.json` using the CLI:

```bash
gatekeeper report --from gatekeeper-report/report.json --format html
```
