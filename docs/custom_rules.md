# Custom Rules & Prompts

Teach Claude your team's specific conventions, architectural guidelines, and security requirements using plain English.

---

## Defining Custom Rules

Add custom guidelines directly under `review.custom_rules` in `gatekeeper.yml`:

```yaml
review:
  custom_rules:
    - "All SQL queries must use parameterized statements or repository interfaces; raw string concatenation is forbidden."
    - "Do not log personal identifiable information (PII) such as email, phone numbers, or credit card numbers."
    - "Every new REST endpoint in /api/v1/ must include rate limiting middleware."
    - "Use Decimal instead of float for all monetary calculations."
```

During audit passes, these rules are injected into the cached system prompt template and rigorously enforced across all reviewed chunks.

---

## Overriding Prompt Templates

Prompt templates live in `src/gatekeeper/llm/prompts/`:
- `security.md`: OWASP Top 10 checklist, injection flaws, access control checks.
- `quality.md`: Maintainability, error handling, performance pitfalls.
- `triage.md`: Scanner false positive triage logic.

Each template accepts Jinja2 variables:
- `{{ prompt_version }}`: Current template version number.
- `{{ custom_rules }}`: Team-configured custom rules list.
