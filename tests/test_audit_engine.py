"""Integration tests for audit pipeline on git fixture repositories."""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

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


def test_audit_rerun_on_unchanged_code_uses_cache(git_fixture_repo: Path) -> None:
    """Verify that auditing unchanged code twice hits the chunk result cache."""
    platform = LocalPlatform(
        base="main",
        head="feature/vulnerable",
        repo_root=git_fixture_repo,
    )
    cfg = GatekeeperConfig()
    cfg.review.target_branches = ["main"]

    # First run: cache miss
    res1 = run_audit(
        platform=platform,
        config=cfg,
        base="main",
        head="feature/vulnerable",
        mock=True,
        repo_root=git_fixture_repo,
        enable_cache=True,
    )
    assert res1.verdict == Verdict.FAIL
    assert res1.metadata.extra.get("cached_chunk_hits") == 0

    # Second run on unchanged code: cache hit!
    res2 = run_audit(
        platform=platform,
        config=cfg,
        base="main",
        head="feature/vulnerable",
        mock=True,
        repo_root=git_fixture_repo,
        enable_cache=True,
    )
    assert res2.verdict == Verdict.FAIL
    assert res2.metadata.extra.get("cached_chunk_hits", 0) > 0


def test_audit_with_scanners_and_triage(git_fixture_repo: Path) -> None:
    """Verify that running audit executes scanners and triage."""
    platform = LocalPlatform(
        base="main",
        head="feature/vulnerable",
        repo_root=git_fixture_repo,
    )
    cfg = GatekeeperConfig()
    cfg.review.target_branches = ["main"]
    cfg.scanners.gitleaks.enabled = True
    cfg.scanners.triage_with_llm = True

    res = run_audit(
        platform=platform,
        config=cfg,
        base="main",
        head="feature/vulnerable",
        mock=True,
        repo_root=git_fixture_repo,
    )
    assert res.verdict == Verdict.FAIL
    assert "scanner_findings_count" in res.metadata.extra


def test_audit_scanner_error_handling(git_fixture_repo: Path) -> None:
    """Verify that scanner errors cause ERROR if fail_on_scanner_error is True."""
    platform = LocalPlatform(
        base="main",
        head="feature/vulnerable",
        repo_root=git_fixture_repo,
    )
    cfg = GatekeeperConfig()
    cfg.review.target_branches = ["main"]
    cfg.gate.fail_on_scanner_error = True

    with patch(
        "gatekeeper.engine.audit.run_all_scanners", side_effect=RuntimeError("Scanner crash")
    ):
        res = run_audit(
            platform=platform,
            config=cfg,
            base="main",
            head="feature/vulnerable",
            mock=True,
            repo_root=git_fixture_repo,
        )
        assert res.verdict == Verdict.ERROR


@respx.mock
def test_audit_failure_triggers_all_notifications(
    git_fixture_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify that a failed audit sends Slack, Teams, and Email notifications."""
    slack_url = "https://hooks.slack.com/services/T/B/X"
    teams_url = "https://custom.webhook.office.com/teams"

    slack_route = respx.post(slack_url).mock(return_value=httpx.Response(200, text="ok"))
    teams_route = respx.post(teams_url).mock(return_value=httpx.Response(200, text="ok"))

    monkeypatch.setenv("GK_SLACK_WEBHOOK", slack_url)
    monkeypatch.setenv("GK_TEAMS_WEBHOOK", teams_url)
    monkeypatch.setenv("GK_SMTP_HOST", "smtp.example.com")

    platform = LocalPlatform(
        base="main",
        head="feature/vulnerable",
        repo_root=git_fixture_repo,
    )
    cfg = GatekeeperConfig()
    cfg.review.target_branches = ["main"]
    cfg.notify.on = ["fail", "error"]

    mock_smtp_instance = MagicMock()
    mock_smtp_cls = MagicMock(return_value=mock_smtp_instance)
    mock_smtp_instance.__enter__.return_value = mock_smtp_instance
    monkeypatch.setattr("smtplib.SMTP", mock_smtp_cls)

    res = run_audit(
        platform=platform,
        config=cfg,
        base="main",
        head="feature/vulnerable",
        mock=True,
        repo_root=git_fixture_repo,
    )

    assert res.verdict == Verdict.FAIL
    # Verify Slack notification sent
    assert slack_route.called
    slack_body = json.loads(slack_route.calls.last.request.read().decode("utf-8"))
    assert "FAIL" in slack_body["text"]

    # Verify Teams Adaptive Card notification sent
    assert teams_route.called
    teams_body = json.loads(teams_route.calls.last.request.read().decode("utf-8"))
    assert teams_body["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"

    # Verify Email notification sent
    assert mock_smtp_instance.send_message.called
