"""Platforms package for Gatekeeper AI."""

import os
from pathlib import Path

from gatekeeper.platforms.base import Platform, PlatformContext
from gatekeeper.platforms.bitbucket import BitbucketPlatform
from gatekeeper.platforms.github import GitHubPlatform
from gatekeeper.platforms.local import LocalPlatform


def detect_platform(
    base: str | None = None,
    head: str | None = None,
    context_lines: int = 20,
    repo_root: Path | None = None,
) -> Platform:
    """Auto-detect whether running in GitHub Actions, Bitbucket Pipelines, or locally."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return GitHubPlatform()
    if os.environ.get("BITBUCKET_BUILD_NUMBER") is not None:
        return BitbucketPlatform()
    return LocalPlatform(base=base, head=head, context_lines=context_lines, repo_root=repo_root)


__all__ = [
    "BitbucketPlatform",
    "GitHubPlatform",
    "LocalPlatform",
    "Platform",
    "PlatformContext",
    "detect_platform",
]
