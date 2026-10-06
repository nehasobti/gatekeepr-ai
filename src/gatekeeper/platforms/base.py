"""Platform interface definition for VCS / CI environments."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from gatekeeper.models import AuditResult


@dataclass
class PlatformContext:
    platform_name: str
    pr_id: str | None = None
    source_branch: str | None = None
    target_branch: str | None = None
    commit_sha: str | None = None


class Platform(ABC):
    """Abstract base platform adapter."""

    @abstractmethod
    def detect_context(self) -> PlatformContext:
        """Detect execution environment, PR numbers, branches and commit SHA."""
        pass

    @abstractmethod
    def get_diff(self, base: str | None = None, head: str | None = None) -> str:
        """Fetch unified diff text for the target PR or commit range."""
        pass

    @abstractmethod
    def post_summary(self, result: AuditResult) -> None:
        """Post or update pull request summary comment."""
        pass

    @abstractmethod
    def post_inline_comments(self, result: AuditResult) -> None:
        """Post inline review comments for findings."""
        pass

    @abstractmethod
    def set_status(self, result: AuditResult) -> None:
        """Update CI check run / commit status / Code Insights report."""
        pass
