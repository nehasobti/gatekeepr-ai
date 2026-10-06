# Quick Start: Bitbucket Pipelines

This guide gets Gatekeeper AI running in Bitbucket Cloud pipelines in under 5 minutes.

---

## 1. Configure Repository Access Token

1. Go to **Repository Settings > Repository Access Tokens**.
2. Create a token named `GATEKEEPER_TOKEN` with scopes:
   - `Pull requests: write`
3. Copy the generated token.
4. Go to **Repository Settings > Repository Variables** and add:
   - `GK_BITBUCKET_TOKEN`: Secured variable containing your token.
   - `ANTHROPIC_API_KEY`: Secured variable containing your Anthropic API key.
   - *(Optional)* `GK_TEAMS_WEBHOOK`: Teams webhook URL.

---

## 2. Add Bitbucket Pipelines Configuration

Add the following step to your `bitbucket-pipelines.yml`:

```yaml
pipelines:
  pull-requests:
    '**':
      - step:
          name: Gatekeeper AI Audit
          clone:
            depth: full
          script:
            - pipe: docker://gatekeeper-ai/gatekeeper-ai-pipe:1.0.0
              variables:
                ANTHROPIC_API_KEY: $ANTHROPIC_API_KEY
                BITBUCKET_ACCESS_TOKEN: $GK_BITBUCKET_TOKEN
                GK_TEAMS_WEBHOOK: $GK_TEAMS_WEBHOOK
          artifacts:
            - gatekeeper-report/**
```

---

## 3. Configure Merge Checks & Branch Restrictions

To enforce merge blocking on Bitbucket:

1. Navigate to **Repository Settings > Branch restrictions**.
2. Select your target branch (e.g., `qa` or `main`).
3. Under **Merge checks**, enable:
   - **Minimum number of successful builds**: `1`
   - **No failed builds**
   - *(Optional)* **Require report to pass from Code Insights**: Select report key `gatekeeper-ai`.
4. Click **Save**.

---

## 4. First Audit Run

When a pull request is submitted:
1. The pipeline runs the Gatekeeper pipe.
2. A single summary comment with status badges is posted on the PR.
3. High and critical findings receive inline discussion comments directly on the diff.
4. A **Code Insights** report (`gatekeeper-ai`) appears in the right sidebar of the PR with detailed annotations.
5. If the gate fails, the pipeline step exits with code `1`, preventing merges.
