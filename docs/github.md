# GitHub Actions Setup & Branch Protection Guide

This guide covers setting up Gatekeeper AI in your GitHub repository, configuring necessary secrets, and enabling branch protection rules to block failing pull requests from reaching `qa` or `main`.

---

## 1. Secrets & Permissions Configuration

### Required Secrets
Add your Anthropic API Key in **Settings** > **Secrets and variables** > **Actions**:
- `ANTHROPIC_API_KEY`: Your Claude API key.

### Token Permissions
The automatic `GITHUB_TOKEN` requires the following explicit permissions in your workflow:
```yaml
permissions:
  contents: read           # To read repository code and diffs
  pull-requests: write     # To post inline comments and summary comments
  checks: write            # To publish the "Gatekeeper AI" check run
  security-events: write   # To upload SARIF to GitHub Code Scanning (Security tab)
```

---

## 2. Workflow Setup

Create `.github/workflows/gatekeeper.yml`:

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
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: tychon/gatekeeper-ai@v1
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: gatekeeper-report
          path: gatekeeper-report/
```

---

## 3. Branch Protection & Merge Blocking

To require that pull requests pass the Gatekeeper AI audit before they can be merged:

### Using GitHub Branch Rulesets (Recommended)
1. Go to **Settings** > **Rules** > **Rulesets**.
2. Click **New ruleset** > **New branch ruleset**.
3. Name: `Gatekeeper Quality Gate`.
4. Target branches: Include default branch (`main`) and target branches (`qa`).
5. Under **Rules**, check:
   - ✅ **Require status checks to pass before merging**.
   - Click **+ Add checks** and select **Gatekeeper AI**.
6. Set **Enforcement status** to **Active**.
7. Click **Save changes**.

### Using Classic Branch Protection Rules
1. Go to **Settings** > **Branches** > **Add branch protection rule**.
2. Set Branch name pattern to `qa` (and another for `main`).
3. Check:
   - ✅ **Require status checks to pass before merging**.
   - Search for status check: `Gatekeeper AI`.
4. Check:
   - ✅ **Require branches to be up to date before merging**.
5. Click **Save changes**.

---

## 4. GitHub Code Scanning (Security Tab) Integration

Gatekeeper automatically uploads a SARIF 2.1.0 report to the GitHub Code Scanning API.
All identified vulnerabilities and weaknesses will appear directly under the **Security** tab > **Code scanning alerts**, complete with rule descriptions, CWE references, and remediation guidance.
