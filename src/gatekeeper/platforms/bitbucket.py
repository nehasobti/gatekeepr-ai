"""Bitbucket Cloud platform adapter skeleton."""

from __future__ import annotations

import os

from gatekeeper.models import AuditResult
from gatekeeper.platforms.base import Platform, PlatformContext


class BitbucketPlatform(Platform):
    """Bitbucket Cloud platform adapter."""

    def __init__(self, token: str | None = None) -> None:
        self.token = token or os.environ.get("BITBUCKET_ACCESS_TOKEN")

    def detect_context(self) -> PlatformContext:
        dest_branch = os.environ.get("BITBUCKET_PR_DESTINATION_BRANCH")
        source_branch = os.environ.get("BITBUCKET_BRANCH")
        pr_id = os.environ.get("BITBUCKET_PR_ID")
        commit = os.environ.get("BITBUCKET_COMMIT")

        return PlatformContext(
            platform_name="bitbucket",
            pr_id=pr_id,
            source_branch=source_branch,
            target_branch=dest_branch,
            commit_sha=commit,
        )

    def get_diff(self, _base: str | None = None, _head: str | None = None) -> str:
        # Full implementation in Phase 2
        return ""

    def post_summary(self, result: AuditResult) -> None:
        pass

    def post_inline_comments(self, result: AuditResult) -> None:
        pass

    def set_status(self, result: AuditResult) -> None:
        pass
