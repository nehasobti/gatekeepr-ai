# Quick Start: GitHub Actions

This guide gets Gatekeeper AI running on GitHub pull requests in under 5 minutes.

---

## 1. Store Secrets in GitHub

Navigate to your repository's **Settings > Secrets and variables > Actions** and add:

- `ANTHROPIC_API_KEY`: Your Anthropic API key with access to Claude 3.5 / 3.7 models.
- *(Optional)* `GK_SLACK_WEBHOOK`: Slack Incoming Webhook URL.
- *(Optional)* `GK_TEAMS_WEBHOOK`: Microsoft Teams Workflows webhook URL.

> Note: `GITHUB_TOKEN` is automatically provided by GitHub Actions.

---

## 2. Add the Workflow File

Create `.github/workflows/gatekeeper.yml` in your repository:

```yaml
name: Gatekeeper AI
on:
  pull_request:
    branches: [qa, main]

permissions:
  contents: read
  pull-requests: write
  checks: write
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Gatekeeper AI Audit
        uses: gatekeeper-ai/gatekeeper-ai@v1
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GK_SLACK_WEBHOOK: ${{ secrets.GK_SLACK_WEBHOOK }}

      - name: Upload Gatekeeper Reports
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: gatekeeper-report
          path: gatekeeper-report/
```

---

## 3. Enable Branch Protection

To block pull requests from merging when Gatekeeper fails:

1. In GitHub, go to **Settings > Branches**.
2. Click **Add branch protection rule** for `qa` (or `main`).
3. Check **Require status checks to pass before merging**.
4. In the search box, search for and select **Gatekeeper AI**.
5. Save changes.

---

## 4. Run First Audit

Open a pull request into `qa` or `main`. Gatekeeper AI will automatically:
1. Parse the diff and filter out lockfiles/binaries.
2. Review changed code chunks with Claude.
3. Post or update a single summary comment in the PR conversation.
4. Post line-by-line review comments with actionable suggestions.
5. Create a check run named `Gatekeeper AI` (`success` or `failure`).
6. Upload SARIF 2.1.0 results directly to the **Security > Code scanning** tab.
