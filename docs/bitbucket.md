# Bitbucket Cloud Setup & Merge Blocking Guide

This guide explains how to configure Gatekeeper AI in Bitbucket Cloud pipelines and set up branch restrictions to block failing pull requests from reaching QA or production.

---

## 1. Prerequisites & Permissions

1. **Repository Access Token**:
   - Navigate to **Repository settings** > **Access tokens**.
   - Create a token with the following scopes:
     - `Pull requests: Write` (to post inline comments and summary comments)
     - `Reports: Write` (to publish Code Insights reports and annotations)
   - Store the token as a secured variable named `BITBUCKET_ACCESS_TOKEN` in **Repository settings** > **Repository variables**.

2. **Anthropic API Key**:
   - Add `ANTHROPIC_API_KEY` to secured variables.

---

## 2. Pipeline Configuration

Add the Gatekeeper Pipe into `bitbucket-pipelines.yml`:

```yaml
pipelines:
  pull-requests:
    '**':
      - step:
          name: Gatekeeper AI Audit
          clone:
            depth: full
          script:
            - pipe: docker://ghcr.io/tychon/gatekeeper-ai-pipe:1.0.0
              variables:
                ANTHROPIC_API_KEY: $ANTHROPIC_API_KEY
                BITBUCKET_ACCESS_TOKEN: $BITBUCKET_ACCESS_TOKEN
          artifacts:
            - gatekeeper-report/**
```

---

## 3. Merge Blocking & Branch Restrictions

To guarantee that failing code cannot be merged into `qa` or `main`:

1. Go to **Repository settings** > **Branch restrictions**.
2. Click **Add a branch restriction**.
3. Select **Branch or pattern**: `qa` (and create a second rule for `main`).
4. Under **Merge checks**, enable:
   - ✅ **No failed builds**: Blocks merges if any pipeline step failed.
   - ✅ **Minimum number of successful builds**: Set to `1`.
   - ✅ **Require report passes from Code Insights**: Select the `gatekeeper-ai` report key.
5. Click **Save**.

---

## 4. How the Quality Gate Operates

1. A developer opens a pull request targeting `qa`.
2. Bitbucket Pipelines triggers the Gatekeeper AI step.
3. Gatekeeper fetches the pull request diff, reviews changes using Claude, and:
   - Posts a summary badge on the PR description/comments.
   - Posts inline comments on specific vulnerable lines.
   - Publishes the `gatekeeper-ai` **Code Insights report**.
4. If findings exceed the configured severity thresholds (e.g. Critical >= 1 or High >= 1):
   - The Code Insights report status is marked **FAILED**.
   - The pipeline step exits with code `1`.
   - Bitbucket merge checks block the developer from merging the PR until the vulnerabilities are resolved.
