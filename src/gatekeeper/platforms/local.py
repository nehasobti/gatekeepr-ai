"""Local platform adapter running git diff commands locally."""

from __future__ import annotations

import subprocess
from pathlib import Path

from gatekeeper.models import AuditResult
from gatekeeper.platforms.base import Platform, PlatformContext


class LocalPlatform(Platform):
    """Local git repository platform adapter."""

    def __init__(
        self,
        base: str | None = None,
        head: str | None = None,
        context_lines: int = 20,
        repo_root: Path | None = None,
    ) -> None:
        self.base = base
        self.head = head
        self.context_lines = context_lines
        self.repo_root = repo_root or Path.cwd()

    def _run_git(self, args: list[str]) -> str:
        res = subprocess.run(
            ["git", *args],
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode != 0:
            raise RuntimeError(f"Git command failed: git {' '.join(args)}\n{res.stderr.strip()}")
        return res.stdout

    def detect_context(self) -> PlatformContext:
        current_branch: str | None = None
        commit_sha: str | None = None
        try:
            current_branch = self._run_git(["rev-parse", "--abbrev-ref", "HEAD"]).strip()
            commit_sha = self._run_git(["rev-parse", "HEAD"]).strip()
        except Exception:
            pass

        return PlatformContext(
            platform_name="local",
            pr_id=None,
            source_branch=self.head or current_branch,
            target_branch=self.base,
            commit_sha=commit_sha,
        )

    def get_diff(self, base: str | None = None, head: str | None = None) -> str:
        b = base or self.base
        h = head or self.head
        u_flag = f"-U{self.context_lines}"

        if b and h:
            # Try three-dot diff first, fall back to two-dot if not applicable
            try:
                return self._run_git(["diff", u_flag, f"{b}...{h}"])
            except RuntimeError:
                return self._run_git(["diff", u_flag, b, h])
        elif b:
            return self._run_git(["diff", u_flag, b])
        else:
            # Diff staged or working tree vs HEAD
            diff_staged = self._run_git(["diff", u_flag, "--cached"])
            if diff_staged.strip():
                return diff_staged
            return self._run_git(["diff", u_flag, "HEAD~1"])

    def post_summary(self, result: AuditResult) -> None:
        pass

    def post_inline_comments(self, result: AuditResult) -> None:
        pass

    def set_status(self, result: AuditResult) -> None:
        pass
