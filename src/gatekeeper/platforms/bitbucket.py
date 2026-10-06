"""Bitbucket Cloud platform adapter."""

from __future__ import annotations

import contextlib
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
    Category,
    Severity,
    Verdict,
)
from gatekeeper.platforms.base import Platform, PlatformContext
from gatekeeper.report.markdown import generate_markdown_content

BITBUCKET_API_BASE = "https://api.bitbucket.org/2.0"
SUMMARY_MARKER = "<!-- gatekeeper-summary-marker -->"


def severity_to_bitbucket_severity(sev: Severity) -> str:
    mapping = {
        Severity.CRITICAL: "CRITICAL",
        Severity.HIGH: "HIGH",
        Severity.MEDIUM: "MEDIUM",
        Severity.LOW: "LOW",
        Severity.INFO: "LOW",
    }
    return mapping.get(sev, "LOW")


def category_to_annotation_type(cat: Category) -> str:
    vuln_cats = {
        Category.INJECTION,
        Category.AUTH,
        Category.SECRES,
        Category.CRYPTO,
        Category.XSS,
        Category.SSRF,
        Category.DESERIALIZATION,
        Category.ACCESS_CONTROL,
    }
    if cat in vuln_cats:
        return "VULNERABILITY"
    elif cat in (Category.BUG, Category.ERROR_HANDLING):
        return "BUG"
    return "CODE_SMELL"


class BitbucketPlatform(Platform):
    """Bitbucket Cloud REST API platform adapter."""

    def __init__(
        self,
        token: str | None = None,
        workspace: str | None = None,
        repo_slug: str | None = None,
        pr_id: str | None = None,
        commit: str | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self.token = token or os.environ.get("BITBUCKET_ACCESS_TOKEN")
        self.workspace = (
            workspace
            or os.environ.get("BITBUCKET_WORKSPACE")
            or os.environ.get("BITBUCKET_REPO_WORKSPACE")
            or os.environ.get("BITBUCKET_REPO_OWNER")
        )
        self.repo_slug = repo_slug or os.environ.get("BITBUCKET_REPO_SLUG")
        self.pr_id = pr_id or os.environ.get("BITBUCKET_PR_ID")
        self.commit = commit or os.environ.get("BITBUCKET_COMMIT")

        self.client = client or httpx.Client(
            base_url=BITBUCKET_API_BASE,
            timeout=30.0,
            follow_redirects=True,
        )

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def detect_context(self) -> PlatformContext:
        dest_branch = os.environ.get("BITBUCKET_PR_DESTINATION_BRANCH")
        source_branch = os.environ.get("BITBUCKET_BRANCH")
        pr_id = self.pr_id
        commit = self.commit

        return PlatformContext(
            platform_name="bitbucket",
            pr_id=pr_id,
            source_branch=source_branch,
            target_branch=dest_branch,
            commit_sha=commit,
        )

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
    )
    def get_diff(self, base: str | None = None, head: str | None = None) -> str:  # noqa: ARG002
        """Fetch raw unified diff from Bitbucket Cloud API."""
        if not self.workspace or not self.repo_slug or not self.pr_id:
            raise ValueError(
                "Missing required Bitbucket repository context (workspace, repo_slug, pr_id)"
            )

        url = f"/repositories/{self.workspace}/{self.repo_slug}/pullrequests/{self.pr_id}/diff"
        headers = self._headers()
        headers["Accept"] = "text/plain"

        resp = self.client.get(url, headers=headers)
        resp.raise_for_status()
        return resp.text

    def post_summary(self, result: AuditResult) -> None:
        """Post or update the pull request summary comment."""
        if not self.workspace or not self.repo_slug or not self.pr_id:
            return

        markdown_text = generate_markdown_content(result)
        comments_url = (
            f"/repositories/{self.workspace}/{self.repo_slug}/pullrequests/{self.pr_id}/comments"
        )

        with contextlib.suppress(Exception):
            existing_id = self._find_existing_summary_comment(comments_url)
            if existing_id:
                update_url = f"{comments_url}/{existing_id}"
                self.client.put(
                    update_url,
                    headers=self._headers(),
                    json={"content": {"raw": markdown_text}},
                )
            else:
                self.client.post(
                    comments_url,
                    headers=self._headers(),
                    json={"content": {"raw": markdown_text}},
                )

    def _find_existing_summary_comment(self, comments_url: str) -> str | None:
        try:
            resp = self.client.get(comments_url, headers=self._headers())
            if resp.status_code == 200:
                data = resp.json()
                values = data.get("values", [])
                for comment in values:
                    raw = comment.get("content", {}).get("raw", "")
                    if SUMMARY_MARKER in raw:
                        return str(comment.get("id"))
        except Exception:
            return None
        return None

    def post_inline_comments(self, result: AuditResult, max_inline: int = 25) -> None:
        """Post individual inline review comments up to max_inline."""
        if not self.workspace or not self.repo_slug or not self.pr_id:
            return

        comments_url = (
            f"/repositories/{self.workspace}/{self.repo_slug}/pullrequests/{self.pr_id}/comments"
        )
        to_post = result.findings[:max_inline]

        for finding in to_post:
            body = (
                f"**[{finding.severity.value.upper()}] {finding.title}**\n\n"
                f"{finding.explanation}\n\n"
                f"**Suggested Fix:**\n```\n{finding.suggested_fix}\n```"
            )
            payload = {
                "content": {"raw": body},
                "inline": {
                    "path": finding.file,
                    "to": finding.start_line,
                },
            }
            with contextlib.suppress(Exception):
                self.client.post(comments_url, headers=self._headers(), json=payload)

    def set_status(self, result: AuditResult) -> None:
        """Publish Code Insights report with annotations."""
        if not self.workspace or not self.repo_slug or not self.commit:
            return

        report_key = "gatekeeper-ai"
        report_url = f"/repositories/{self.workspace}/{self.repo_slug}/commit/{self.commit}/reports/{report_key}"

        bb_result = "PASSED" if result.verdict == Verdict.PASS else "FAILED"
        report_payload = {
            "title": "Gatekeeper AI Quality Gate",
            "details": f"Quality gate evaluation finished with verdict: {result.verdict.value}",
            "report_type": "SECURITY",
            "result": bb_result,
            "data": [
                {"title": "Critical", "type": "NUMBER", "value": result.summary.critical},
                {"title": "High", "type": "NUMBER", "value": result.summary.high},
                {"title": "Medium", "type": "NUMBER", "value": result.summary.medium},
                {"title": "Low", "type": "NUMBER", "value": result.summary.low},
                {"title": "Total Issues", "type": "NUMBER", "value": result.summary.total},
            ],
        }

        try:
            self.client.put(report_url, headers=self._headers(), json=report_payload)
        except Exception:
            return

        # Publish annotations if any findings exist
        if result.findings:
            annotations_url = f"{report_url}/annotations"
            annotations: list[dict[str, Any]] = []
            for f in result.findings[:100]:
                annotations.append(
                    {
                        "external_id": f.id,
                        "title": f.title[:255],
                        "annotation_type": category_to_annotation_type(f.category),
                        "summary": f.explanation[:2000],
                        "severity": severity_to_bitbucket_severity(f.severity),
                        "path": f.file,
                        "line": f.start_line,
                    }
                )

            with contextlib.suppress(Exception):
                self.client.post(annotations_url, headers=self._headers(), json=annotations)
