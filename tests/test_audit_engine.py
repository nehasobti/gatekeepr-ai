"""Integration tests for audit pipeline on git fixture repositories."""

import subprocess
from pathlib import Path

import pytest

from gatekeeper.config import GatekeeperConfig
from gatekeeper.engine.audit import run_audit
from gatekeeper.models import Verdict
from gatekeeper.platforms.local import LocalPlatform


@pytest.fixture
def git_fixture_repo(tmp_path: Path) -> Path:
    """Create a temporary git repository with main, vulnerable, and clean branches."""
    repo = tmp_path / "repo"
    repo.mkdir()

    def run_cmd(args: list[str]) -> None:
        subprocess.run(
            ["git", *args],
            cwd=str(repo),
            check=True,
            capture_output=True,
            text=True,
        )

    run_cmd(["init", "-b", "main"])
    run_cmd(["config", "user.name", "Test User"])
    run_cmd(["config", "user.email", "test@example.com"])

    # Initial main commit
    (repo / "README.md").write_text("# Test Repo\n", encoding="utf-8")
    run_cmd(["add", "README.md"])
    run_cmd(["commit", "-m", "Initial commit"])

    # Create vulnerable branch
    run_cmd(["checkout", "-b", "feature/vulnerable"])
    src_vuln = Path(__file__).parent / "fixtures" / "vulnerable" / "app.py"
    (repo / "app.py").write_text(src_vuln.read_text(encoding="utf-8"), encoding="utf-8")
    run_cmd(["add", "app.py"])
    run_cmd(["commit", "-m", "Add vulnerable app"])

    # Create clean branch from main
    run_cmd(["checkout", "main"])
    run_cmd(["checkout", "-b", "feature/clean"])
    src_clean = Path(__file__).parent / "fixtures" / "clean" / "app.py"
    (repo / "app.py").write_text(src_clean.read_text(encoding="utf-8"), encoding="utf-8")
    run_cmd(["add", "app.py"])
    run_cmd(["commit", "-m", "Add clean app"])

    run_cmd(["checkout", "main"])
    return repo


def test_audit_vulnerable_branch_fails(git_fixture_repo: Path) -> None:
    platform = LocalPlatform(
        base="main",
        head="feature/vulnerable",
        repo_root=git_fixture_repo,
    )
    cfg = GatekeeperConfig()
    cfg.review.target_branches = ["main"]

    res = run_audit(
        platform=platform,
        config=cfg,
        base="main",
        head="feature/vulnerable",
        mock=True,
        repo_root=git_fixture_repo,
    )

    assert res.verdict == Verdict.FAIL
    assert res.summary.critical >= 1
    assert res.summary.high >= 1
    assert len(res.findings) >= 3


def test_audit_clean_branch_passes(git_fixture_repo: Path) -> None:
    platform = LocalPlatform(
        base="main",
        head="feature/clean",
        repo_root=git_fixture_repo,
    )
    cfg = GatekeeperConfig()
    cfg.review.target_branches = ["main"]

    res = run_audit(
        platform=platform,
        config=cfg,
        base="main",
        head="feature/clean",
        mock=True,
        repo_root=git_fixture_repo,
    )

    assert res.verdict == Verdict.PASS
    assert len(res.findings) == 0
    assert res.summary.total == 0


def test_audit_skipped_when_target_not_gated(git_fixture_repo: Path) -> None:
    platform = LocalPlatform(
        base="dev-sandbox",
        head="feature/clean",
        repo_root=git_fixture_repo,
    )
    cfg = GatekeeperConfig()
    cfg.review.target_branches = ["main", "qa"]

    res = run_audit(
        platform=platform,
        config=cfg,
        base="dev-sandbox",
        head="feature/clean",
        mock=True,
        repo_root=git_fixture_repo,
    )

    assert res.verdict == Verdict.SKIPPED


def test_audit_dry_run_mode(git_fixture_repo: Path) -> None:
    platform = LocalPlatform(
        base="main",
        head="feature/vulnerable",
        repo_root=git_fixture_repo,
    )
    cfg = GatekeeperConfig()
    cfg.review.target_branches = ["main"]

    res = run_audit(
        platform=platform,
        config=cfg,
        base="main",
        head="feature/vulnerable",
        dry_run=True,
        mock=True,
        repo_root=git_fixture_repo,
    )

    assert res.verdict == Verdict.PASS
    assert res.metadata.extra.get("dry_run") is True
