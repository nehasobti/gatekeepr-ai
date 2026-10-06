"""GitHub platform adapter skeleton."""

from __future__ import annotations

import os

from gatekeeper.models import AuditResult
from gatekeeper.platforms.base import Platform, PlatformContext


class GitHubPlatform(Platform):
    """GitHub Actions platform adapter."""

    def __init__(self, token: str | None = None) -> None:
        self.token = token or os.environ.get("GITHUB_TOKEN")

    def detect_context(self) -> PlatformContext:
        base_ref = os.environ.get("GITHUB_BASE_REF")
        head_ref = os.environ.get("GITHUB_HEAD_REF")
        sha = os.environ.get("GITHUB_SHA")
        # In pull requests, ref is refs/pull/:id/merge
        ref = os.environ.get("GITHUB_REF", "")
        pr_id = None
        if "pull/" in ref:
            parts = ref.split("/")
            if len(parts) >= 3:
                pr_id = parts[2]

        return PlatformContext(
            platform_name="github",
            pr_id=pr_id,
            source_branch=head_ref,
            target_branch=base_ref,
            commit_sha=sha,
        )

    def get_diff(self, base: str | None = None, head: str | None = None) -> str:  # noqa: ARG002
        # Full implementation in Phase 3
        return ""

    def post_summary(self, result: AuditResult) -> None:
        pass

    def post_inline_comments(self, result: AuditResult) -> None:
        pass

    def set_status(self, result: AuditResult) -> None:
        pass
