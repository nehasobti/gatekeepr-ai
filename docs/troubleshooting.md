# Troubleshooting

Common issues and solutions when running Gatekeeper AI.

---

## 1. Authentication & Secrets

### Problem: `ANTHROPIC_API_KEY environment variable is not set`
- **Solution**: Ensure your CI pipeline has mapped the secret to the runner step:
  - GitHub Actions: `ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}`
  - Bitbucket Pipelines: `ANTHROPIC_API_KEY: $ANTHROPIC_API_KEY` (ensure the variable is added in Repository Settings).

### Problem: `401 Unauthorized` on Bitbucket PR Comments
- **Solution**: The `BITBUCKET_ACCESS_TOKEN` must have `Pull requests: write` permission.

### Problem: `403 Resource not accessible by integration` on GitHub
- **Solution**: Check that the workflow sets explicit permissions in the job:
  ```yaml
  permissions:
    pull-requests: write
    checks: write
    security-events: write
  ```

---

## 2. Diffs & Limits

### Problem: `max_diff_lines` Truncation
- **Symptom**: Report says "Some files were not reviewed due to diff line limits."
- **Solution**: Increase `review.max_diff_lines` in `gatekeeper.yml` or exclude generated files/lockfiles using `review.exclude`.

### Problem: Large PRs Timing Out
- **Solution**: Gatekeeper chunks files and reviews up to 4 chunks in parallel. Ensure your CI step timeout is set to at least 5 minutes.

---

## 3. Inline Comments Not Appearing

- Check `outputs.pr_comment`: ensure it is set to `summary_and_inline`.
- GitHub only allows inline comments on lines that were added or changed in the PR diff. Lines outside the diff will only appear in the summary comment and report files.
