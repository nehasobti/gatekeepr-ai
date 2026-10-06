# Cost Guide & Token Optimization

Gatekeeper AI incorporates multiple layers of caching and budgeting to ensure predictable, minimal token consumption.

---

## 1. Token Budgeting

In `gatekeeper.yml`:

```yaml
budget:
  max_input_tokens_per_run: 200000
  on_budget_exceeded: warn   # warn | fail | skip_remaining
```

- `warn`: Logs a warning when the budget ceiling is exceeded, continuing review.
- `fail`: Halts execution and fails the audit immediately.
- `skip_remaining`: Ceases LLM evaluation of remaining chunks.

---

## 2. Prompt Caching

Gatekeeper AI marks its system instructions, OWASP rulesets, and custom guidelines with Anthropic's **ephemeral prompt caching** (`cache_control: { type: "ephemeral" }`).

- When analyzing multiple chunks or review passes, the system prompt is only billed at full write cost once.
- Subsequent chunk reviews and review passes read the cached system prompt at a **90% discount** (\$0.30 per 1M tokens vs \$3.00 per 1M tokens).

---

## 3. Result Caching

Review findings for each chunk are cached locally in `.gatekeeper/cache` using SHA-256 hashes computed from:
- Exact chunk diff content
- Pass name (`security` vs `quality`)
- Prompt version
- Model name
- Sorted list of custom rules

When a developer pushes a minor commit or re-runs a workflow on an existing PR, unmodified chunks are fetched from cache with **zero latency and zero API calls**.

---

## 4. Cost Estimation & Monthly Projections

Every audit calculates and prints the exact USD cost:

```text
Tokens:  Input: 4,210 | Output: 620 | Cached: 3,100
Cost:    $0.0154 USD
```

### Typical Monthly Estimate:
- Average PR: 150 changed lines = ~3,000 input tokens.
- Prompt cache hit rate: ~75%.
- Estimated cost per PR: ~**\$0.01 – \$0.02 USD**.
- A team shipping 200 PRs per month spends approximately **\$2.00 – \$4.00 USD/month** in Claude API usage.
