"""Unit tests for platform detection and adapters."""

import pytest

from gatekeeper.platforms import detect_platform
from gatekeeper.platforms.bitbucket import BitbucketPlatform
from gatekeeper.platforms.github import GitHubPlatform
from gatekeeper.platforms.local import LocalPlatform


def test_detect_platform_local() -> None:
    platform = detect_platform()
    assert isinstance(platform, LocalPlatform)


def test_detect_platform_github(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REF", "refs/pull/42/merge")
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    monkeypatch.setenv("GITHUB_HEAD_REF", "feature/auth")
    monkeypatch.setenv("GITHUB_SHA", "abcdef123456")

    platform = detect_platform()
    assert isinstance(platform, GitHubPlatform)
    ctx = platform.detect_context()
    assert ctx.platform_name == "github"
    assert ctx.pr_id == "42"
    assert ctx.target_branch == "main"
    assert ctx.source_branch == "feature/auth"
    assert ctx.commit_sha == "abcdef123456"


def test_detect_platform_bitbucket(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BITBUCKET_BUILD_NUMBER", "101")
    monkeypatch.setenv("BITBUCKET_PR_ID", "17")
    monkeypatch.setenv("BITBUCKET_PR_DESTINATION_BRANCH", "qa")
    monkeypatch.setenv("BITBUCKET_BRANCH", "feature/db")
    monkeypatch.setenv("BITBUCKET_COMMIT", "1234567890")

    platform = detect_platform()
    assert isinstance(platform, BitbucketPlatform)
    ctx = platform.detect_context()
    assert ctx.platform_name == "bitbucket"
    assert ctx.pr_id == "17"
    assert ctx.target_branch == "qa"
    assert ctx.source_branch == "feature/db"
