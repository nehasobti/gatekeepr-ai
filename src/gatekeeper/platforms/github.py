"""GitHub Actions platform adapter."""

from __future__ import annotations

import base64
import contextlib
import gzip
import json
import os
from typing import Any

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from gatekeeper.models import (
    AuditResult,
    Verdict,
)
from gatekeeper.platforms.base import Platform, PlatformContext
from gatekeeper.report.markdown import generate_markdown_content
from gatekeeper.report.sarif import generate_sarif_dict

GITHUB_API_DEFAULT = "https://api.github.com"
SUMMARY_MARKER = "<!-- gatekeeper-summary-marker -->"


class GitHubPlatform(Platform):
    """GitHub REST API platform adapter for GitHub Actions."""

    def __init__(
        self,
        token: str | None = None,
        repository: str | None = None,
        pr_id: str | None = None,
        commit_sha: str | None = None,
        api_url: str | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.repository = repository or os.environ.get("GITHUB_REPOSITORY")
        self.api_url = (api_url or os.environ.get("GITHUB_API_URL") or GITHUB_API_DEFAULT).rstrip(
            "/"
        )
        self.commit_sha = commit_sha or os.environ.get("GITHUB_SHA")

        # Extract PR ID from argument or GITHUB_REF (refs/pull/:id/merge)
        self.pr_id: str | None
        if pr_id:
            self.pr_id = pr_id
        else:
            ref = os.environ.get("GITHUB_REF", "")
            self.pr_id = None
            if "pull/" in ref:
                parts = ref.split("/")
                if len(parts) >= 3:
                    self.pr_id = parts[2]

        self.client = client or httpx.Client(
            base_url=self.api_url,
            timeout=30.0,
            follow_redirects=True,
        )

    def _headers(self, accept: str = "application/vnd.github+json") -> dict[str, str]:
        headers = {
            "Accept": accept,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def detect_context(self) -> PlatformContext:
        base_ref = os.environ.get("GITHUB_BASE_REF")
        head_ref = os.environ.get("GITHUB_HEAD_REF")

        return PlatformContext(
            platform_name="github",
            pr_id=self.pr_id,
            source_branch=head_ref,
            target_branch=base_ref,
            commit_sha=self.commit_sha,
        )

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
    )
    def get_diff(self, base: str | None = None, head: str | None = None) -> str:  # noqa: ARG002
        """Fetch raw PR diff from GitHub API using Accept: application/vnd.github.v3.diff."""
        if not self.repository or not self.pr_id:
            raise ValueError("Missing required GitHub repository or pull request number")

        url = f"/repos/{self.repository}/pulls/{self.pr_id}"
        resp = self.client.get(
            url,
            headers=self._headers(accept="application/vnd.github.v3.diff"),
        )
        resp.raise_for_status()
        return resp.text

    def post_summary(self, result: AuditResult) -> None:
        """Post or update pull request summary comment in-place."""
        if not self.repository or not self.pr_id:
            return

        markdown_body = generate_markdown_content(result)
        comments_url = f"/repos/{self.repository}/issues/{self.pr_id}/comments"

        with contextlib.suppress(Exception):
            existing_id = self._find_existing_summary_comment(comments_url)
            if existing_id:
                # Update existing comment in place
                update_url = f"/repos/{self.repository}/issues/comments/{existing_id}"
                self.client.patch(
                    update_url,
                    headers=self._headers(),
                    json={"body": markdown_body},
                )
            else:
                # Post new comment
                self.client.post(
                    comments_url,
                    headers=self._headers(),
                    json={"body": markdown_body},
                )

    def _find_existing_summary_comment(self, comments_url: str) -> str | None:
        try:
            resp = self.client.get(comments_url, headers=self._headers())
            if resp.status_code == 200:
                comments = resp.json()
                if isinstance(comments, list):
                    for c in comments:
                        if isinstance(c, dict) and SUMMARY_MARKER in c.get("body", ""):
                            return str(c.get("id"))
        except Exception:
            return None
        return None

    def post_inline_comments(self, result: AuditResult, max_inline: int = 25) -> None:
        """Post pull request review with inline comments on changed lines."""
        if not self.repository or not self.pr_id or not self.commit_sha:
            return

        review_url = f"/repos/{self.repository}/pulls/{self.pr_id}/reviews"
        to_post = result.findings[:max_inline]

        review_comments: list[dict[str, Any]] = []
        for finding in to_post:
            body = (
                f"**[{finding.severity.value.upper()}] {finding.title}**\n\n"
                f"{finding.explanation}\n\n"
                f"**Suggested Fix:**\n```\n{finding.suggested_fix}\n```"
            )
            review_comments.append(
                {
                    "path": finding.file,
                    "line": finding.start_line,
                    "body": body,
                }
            )

        review_payload = {
            "commit_id": self.commit_sha,
            "event": "COMMENT",
            "body": f"Gatekeeper AI PR Review - Verdict: {result.verdict.value}",
            "comments": review_comments,
        }

        with contextlib.suppress(Exception):
            self.client.post(review_url, headers=self._headers(), json=review_payload)

    def set_status(self, result: AuditResult) -> None:
        """Create check run with PASS/FAIL conclusion and upload SARIF to code scanning."""
        self._create_check_run(result)
        self._upload_sarif(result)

    def _create_check_run(self, result: AuditResult) -> None:
        if not self.repository or not self.commit_sha:
            return

        check_url = f"/repos/{self.repository}/check-runs"
        conclusion = "success" if result.verdict in (Verdict.PASS, Verdict.SKIPPED) else "failure"

        summary_text = (
            f"Gatekeeper AI Quality Gate Verdict: **{result.verdict.value}**\n\n"
            f"- Critical: {result.summary.critical}\n"
            f"- High: {result.summary.high}\n"
            f"- Medium: {result.summary.medium}\n"
            f"- Low: {result.summary.low}\n"
            f"- Total Findings: {result.summary.total}"
        )

        payload = {
            "name": "Gatekeeper AI",
            "head_sha": self.commit_sha,
            "status": "completed",
            "conclusion": conclusion,
            "output": {
                "title": f"Gatekeeper AI: {result.verdict.value}",
                "summary": summary_text,
                "text": generate_markdown_content(result),
            },
        }

        with contextlib.suppress(Exception):
            self.client.post(check_url, headers=self._headers(), json=payload)

    def _upload_sarif(self, result: AuditResult) -> None:
        if not self.repository or not self.commit_sha:
            return

        sarif_url = f"/repos/{self.repository}/code-scanning/sarifs"
        sarif_data = generate_sarif_dict(result)
        sarif_json = json.dumps(sarif_data)

        # GitHub Code Scanning API requires gzipped, base64-encoded SARIF payload
        compressed = gzip.compress(sarif_json.encode("utf-8"))
        encoded_sarif = base64.b64encode(compressed).decode("utf-8")

        ref = f"refs/pull/{self.pr_id}/head" if self.pr_id else "refs/heads/main"
        payload = {
            "commit_sha": self.commit_sha,
            "ref": ref,
            "sarif": encoded_sarif,
        }

        with contextlib.suppress(Exception):
            self.client.post(sarif_url, headers=self._headers(), json=payload)
