# Gatekeeper AI Bitbucket Pipe

> Automated AI quality gate for Bitbucket pull requests.

## Overview

The Gatekeeper AI Pipe reviews newly added and modified lines of code in your Bitbucket pull requests using Claude. It detects security vulnerabilities, critical bugs, and code smells, reports them inline and on the PR overview, and publishes a Bitbucket Code Insights report to block PR merges when severity thresholds are exceeded.

## Usage

Add the pipe to your `bitbucket-pipelines.yml`:

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

## Required Variables

- `ANTHROPIC_API_KEY`: Your Anthropic API Key (stored as a secured workspace or repository variable).
- `BITBUCKET_ACCESS_TOKEN`: A Repository Access Token with `Pull requests: write` and `Reports: write` permissions.

## Optional Variables

- `CONFIG_PATH`: Path to custom `gatekeeper.yml` (default: `gatekeeper.yml`).
- `MOCK_LLM`: `true` to run offline without calling Claude (default: `false`).
