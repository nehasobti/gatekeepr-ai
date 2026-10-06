"""Integration tests for GitHub Actions platform adapter using respx HTTP mocks."""

import base64
import gzip
import json
from pathlib import Path

import httpx
import pytest
import respx

from gatekeeper.config import GatekeeperConfig
from gatekeeper.engine.audit import run_audit
from gatekeeper.models import (
    AuditMetadata,
    AuditResult,
    AuditSummary,
    Category,
    Confidence,
    Finding,
    Severity,
    Verdict,
)
from gatekeeper.platforms.github import GITHUB_API_DEFAULT, GitHubPlatform


@pytest.fixture
def gh_platform() -> GitHubPlatform:
    return GitHubPlatform(
        token="gh-test-token",
        repository="tychon/sample-repo",
        pr_id="42",
        commit_sha="fedcba654321",
    )


@respx.mock
def test_github_get_diff(gh_platform: GitHubPlatform) -> None:
    diff_route = respx.get(f"{GITHUB_API_DEFAULT}/repos/tychon/sample-repo/pulls/42").mock(
        return_value=httpx.Response(200, text="diff --git a/app.py b/app.py\n+print('hello')\n")
    )

    diff = gh_platform.get_diff()
    assert "print('hello')" in diff
    assert diff_route.called
    assert "Bearer gh-test-token" in diff_route.calls.last.request.headers["Authorization"]
    assert "application/vnd.github.v3.diff" in diff_route.calls.last.request.headers["Accept"]


@respx.mock
def test_github_post_new_summary_comment(gh_platform: GitHubPlatform) -> None:
    comments_url = f"{GITHUB_API_DEFAULT}/repos/tychon/sample-repo/issues/42/comments"
    respx.get(comments_url).mock(return_value=httpx.Response(200, json=[]))
    post_route = respx.post(comments_url).mock(return_value=httpx.Response(201, json={"id": 123}))

    result = AuditResult(
        verdict=Verdict.PASS,
        findings=[],
        summary=AuditSummary(),
        metadata=AuditMetadata(),
    )

    gh_platform.post_summary(result)
    assert post_route.called
    posted_data = json.loads(post_route.calls.last.request.read().decode("utf-8"))
    assert "<!-- gatekeeper-summary-marker -->" in posted_data["body"]
    assert "PASS" in posted_data["body"]


@respx.mock
def test_github_update_existing_summary_comment(gh_platform: GitHubPlatform) -> None:
    comments_url = f"{GITHUB_API_DEFAULT}/repos/tychon/sample-repo/issues/42/comments"
    existing_comment = {
        "id": 555,
        "body": "Previous report\n<!-- gatekeeper-summary-marker -->",
    }
    respx.get(comments_url).mock(return_value=httpx.Response(200, json=[existing_comment]))
    patch_route = respx.patch(
        f"{GITHUB_API_DEFAULT}/repos/tychon/sample-repo/issues/comments/555"
    ).mock(return_value=httpx.Response(200, json={"id": 555}))

    result = AuditResult(
        verdict=Verdict.FAIL,
        findings=[],
        summary=AuditSummary(),
        metadata=AuditMetadata(),
    )

    gh_platform.post_summary(result)
    assert patch_route.called
    patch_data = json.loads(patch_route.calls.last.request.read().decode("utf-8"))
    assert "FAIL" in patch_data["body"]


@respx.mock
def test_github_post_review_inline_comments(gh_platform: GitHubPlatform) -> None:
    reviews_url = f"{GITHUB_API_DEFAULT}/repos/tychon/sample-repo/pulls/42/reviews"
    review_route = respx.post(reviews_url).mock(return_value=httpx.Response(200, json={"id": 999}))

    f = Finding.create(
        file="src/app.py",
        start_line=10,
        end_line=10,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        category=Category.INJECTION,
        title="SQL Injection",
        explanation="Untrusted input in SQL",
        suggested_fix="Bind parameters",
    )
    result = AuditResult(
        verdict=Verdict.FAIL,
        findings=[f],
        summary=AuditSummary.from_findings([f]),
        metadata=AuditMetadata(),
    )

    gh_platform.post_inline_comments(result, max_inline=10)
    assert review_route.called
    review_data = json.loads(review_route.calls.last.request.read().decode("utf-8"))
    assert review_data["commit_id"] == "fedcba654321"
    assert len(review_data["comments"]) == 1
    assert review_data["comments"][0]["path"] == "src/app.py"
    assert review_data["comments"][0]["line"] == 10
    assert "SQL Injection" in review_data["comments"][0]["body"]


@respx.mock
def test_github_check_run_and_sarif_upload(gh_platform: GitHubPlatform) -> None:
    check_url = f"{GITHUB_API_DEFAULT}/repos/tychon/sample-repo/check-runs"
    sarif_url = f"{GITHUB_API_DEFAULT}/repos/tychon/sample-repo/code-scanning/sarifs"

    check_route = respx.post(check_url).mock(return_value=httpx.Response(201, json={"id": 777}))
    sarif_route = respx.post(sarif_url).mock(return_value=httpx.Response(202, json={"id": 888}))

    f = Finding.create(
        file="src/auth.py",
        start_line=5,
        end_line=5,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.AUTH,
        owasp="A01:2021 Broken Access Control",
        cwe="CWE-306",
        title="Missing Auth",
        explanation="Endpoint unauthenticated",
        suggested_fix="Add login_required decorator",
    )
    result = AuditResult(
        verdict=Verdict.FAIL,
        findings=[f],
        summary=AuditSummary.from_findings([f]),
        metadata=AuditMetadata(),
    )

    gh_platform.set_status(result)

    # 1. Check run verification
    assert check_route.called
    check_data = json.loads(check_route.calls.last.request.read().decode("utf-8"))
    assert check_data["name"] == "Gatekeeper AI"
    assert check_data["head_sha"] == "fedcba654321"
    assert check_data["conclusion"] == "failure"
    assert "Missing Auth" in check_data["output"]["text"]

    # 2. SARIF verification
    assert sarif_route.called
    sarif_req_data = json.loads(sarif_route.calls.last.request.read().decode("utf-8"))
    assert sarif_req_data["commit_sha"] == "fedcba654321"

    # Decode gzipped base64 SARIF
    compressed_bytes = base64.b64decode(sarif_req_data["sarif"])
    decompressed_str = gzip.decompress(compressed_bytes).decode("utf-8")
    sarif_obj = json.loads(decompressed_str)
    assert sarif_obj["version"] == "2.1.0"
    assert sarif_obj["runs"][0]["tool"]["driver"]["name"] == "Gatekeeper AI"
    assert len(sarif_obj["runs"][0]["results"]) == 1


@respx.mock
def test_github_audit_flow_fails_planted_issues(tmp_path: Path) -> None:
    """Verify that a GitHub PR with planted vulnerabilities triggers failing check run and SARIF."""
    vulnerable_code = (Path(__file__).parent / "fixtures" / "vulnerable" / "app.py").read_text(
        encoding="utf-8"
    )
    diff_text = f"""diff --git a/app.py b/app.py
new file mode 100644
--- /dev/null
+++ b/app.py
@@ -0,0 +1,{len(vulnerable_code.splitlines())} @@
""" + "\n".join(f"+{line}" for line in vulnerable_code.splitlines())

    respx.get(f"{GITHUB_API_DEFAULT}/repos/tychon/sample-repo/pulls/42").mock(
        return_value=httpx.Response(200, text=diff_text)
    )
    comments_url = f"{GITHUB_API_DEFAULT}/repos/tychon/sample-repo/issues/42/comments"
    respx.get(comments_url).mock(return_value=httpx.Response(200, json=[]))
    respx.post(comments_url).mock(return_value=httpx.Response(201, json={"id": 1}))
    respx.post(f"{GITHUB_API_DEFAULT}/repos/tychon/sample-repo/pulls/42/reviews").mock(
        return_value=httpx.Response(200, json={"id": 1})
    )

    check_route = respx.post(f"{GITHUB_API_DEFAULT}/repos/tychon/sample-repo/check-runs").mock(
        return_value=httpx.Response(201, json={"id": 1})
    )
    sarif_route = respx.post(
        f"{GITHUB_API_DEFAULT}/repos/tychon/sample-repo/code-scanning/sarifs"
    ).mock(return_value=httpx.Response(202, json={"id": 1}))

    platform = GitHubPlatform(
        token="token",
        repository="tychon/sample-repo",
        pr_id="42",
        commit_sha="fedcba654321",
    )
    cfg = GatekeeperConfig()
    cfg.outputs.output_dir = str(tmp_path / "reports")

    result = run_audit(
        platform=platform,
        config=cfg,
        mock=True,
        repo_root=tmp_path,
    )

    assert result.verdict == Verdict.FAIL
    assert result.summary.critical >= 1
    assert check_route.called
    check_payload = json.loads(check_route.calls.last.request.read().decode("utf-8"))
    assert check_payload["conclusion"] == "failure"
    assert sarif_route.called


@respx.mock
def test_github_audit_flow_passes_clean_code(tmp_path: Path) -> None:
    """Verify that a GitHub PR with clean code triggers successful check run."""
    clean_code = (Path(__file__).parent / "fixtures" / "clean" / "app.py").read_text(
        encoding="utf-8"
    )
    diff_text = f"""diff --git a/app.py b/app.py
new file mode 100644
--- /dev/null
+++ b/app.py
@@ -0,0 +1,{len(clean_code.splitlines())} @@
""" + "\n".join(f"+{line}" for line in clean_code.splitlines())

    respx.get(f"{GITHUB_API_DEFAULT}/repos/tychon/sample-repo/pulls/42").mock(
        return_value=httpx.Response(200, text=diff_text)
    )
    comments_url = f"{GITHUB_API_DEFAULT}/repos/tychon/sample-repo/issues/42/comments"
    respx.get(comments_url).mock(return_value=httpx.Response(200, json=[]))
    respx.post(comments_url).mock(return_value=httpx.Response(201, json={"id": 1}))

    check_route = respx.post(f"{GITHUB_API_DEFAULT}/repos/tychon/sample-repo/check-runs").mock(
        return_value=httpx.Response(201, json={"id": 1})
    )
    sarif_route = respx.post(
        f"{GITHUB_API_DEFAULT}/repos/tychon/sample-repo/code-scanning/sarifs"
    ).mock(return_value=httpx.Response(202, json={"id": 1}))

    platform = GitHubPlatform(
        token="token",
        repository="tychon/sample-repo",
        pr_id="42",
        commit_sha="fedcba654321",
    )
    cfg = GatekeeperConfig()
    cfg.outputs.output_dir = str(tmp_path / "reports")

    result = run_audit(
        platform=platform,
        config=cfg,
        mock=True,
        repo_root=tmp_path,
    )

    assert result.verdict == Verdict.PASS
    assert len(result.findings) == 0
    assert check_route.called
    check_payload = json.loads(check_route.calls.last.request.read().decode("utf-8"))
    assert check_payload["conclusion"] == "success"
    assert sarif_route.called
