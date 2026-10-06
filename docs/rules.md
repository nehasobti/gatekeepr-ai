# Severity & Gate Rules

Gatekeeper AI determines pull request outcomes by evaluating findings against strict severity tiers, confidence filters, and failure thresholds.

---

## Severity Levels

| Severity | Description | Examples |
| --- | --- | --- |
| **Critical** | Exploitable vulnerability leading to system compromise, data leak, remote code execution, or credential loss. | SQL Injection, Insecure Deserialization, Committed AWS/GitHub Secrets, Unprotected Admin Routes. |
| **High** | High-impact flaw requiring specific conditions, stored XSS, SSRF, or missing authorization decorators. | Reflected XSS, SSRF, Missing Authentication on endpoints, Insecure Hash Algorithms used for passwords. |
| **Medium** | Security bugs or severe code quality degradation that increase attack surface or error risk. | Missing CSRF protection, Insecure cookie flags, Resource leaks, SQL queries without type validation. |
| **Low** | Minor security improvements or code hygiene defects. | Bare exception clauses, Verbose error disclosures, Missing log sanitization. |
| **Info** | Informational notes, best practice suggestions, and minor stylistic concerns. | Code clarity recommendations, Deprecation notices. |

---

## Confidence Filtering

Every finding is assigned a confidence rating (`high`, `medium`, or `low`):

- **High Confidence**: Clear, undeniable issue based directly on visible diff code.
- **Medium Confidence**: Strong indicator of an issue requiring standard assumptions about surrounding code.
- **Low Confidence**: Speculative issue where the context cannot confirm validity.

By default, `gate.min_confidence: medium` instructs Gatekeeper to automatically discard speculative low-confidence findings before gate evaluation.

---

## Gate Verdict Evaluation

The gate evaluator checks active (non-suppressed) findings against `gate.fail_on`:

```yaml
gate:
  fail_on:
    critical: 1
    high: 1
    medium: 10
```

1. If active findings meet or exceed any configured threshold: **`Verdict.FAIL`** (exit code 1).
2. If all counts are strictly below thresholds: **`Verdict.PASS`** (exit code 0).
3. If an unrecoverable runtime, platform, or Claude API error occurs: **`Verdict.ERROR`** (exit code 2 by default).

### Error Policies
- `fail_on_llm_error: true` ensures that if the Claude API is unreachable, unreviewed code cannot slip through undetected.
- `fail_on_scanner_error: false` allows the audit to complete using Claude even if a local static scanner fails to execute.
