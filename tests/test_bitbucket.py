"""Integration tests for Bitbucket Cloud platform adapter using respx HTTP mocks."""

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
from gatekeeper.platforms.bitbucket import (
    BITBUCKET_API_BASE,
    BitbucketPlatform,
)


@pytest.fixture
def bb_platform() -> BitbucketPlatform:
    return BitbucketPlatform(
        token="test-bb-token",
        workspace="my-team",
        repo_slug="sample-repo",
        pr_id="42",
        commit="a1b2c3d4e5f6",
    )


@respx.mock
def test_bitbucket_get_diff(bb_platform: BitbucketPlatform) -> None:
    diff_route = respx.get(
        f"{BITBUCKET_API_BASE}/repositories/my-team/sample-repo/pullrequests/42/diff"
    ).mock(return_value=httpx.Response(200, text="diff --git a/app.py b/app.py\n+print('hello')\n"))

    diff = bb_platform.get_diff()
    assert "print('hello')" in diff
    assert diff_route.called
    assert "Bearer test-bb-token" in diff_route.calls.last.request.headers["Authorization"]


@respx.mock
def test_bitbucket_post_new_summary_comment(bb_platform: BitbucketPlatform) -> None:
    comments_url = f"{BITBUCKET_API_BASE}/repositories/my-team/sample-repo/pullrequests/42/comments"
    respx.get(comments_url).mock(return_value=httpx.Response(200, json={"values": []}))

    post_route = respx.post(comments_url).mock(return_value=httpx.Response(201, json={"id": 1001}))

    result = AuditResult(
        verdict=Verdict.PASS,
        findings=[],
        summary=AuditSummary(),
        metadata=AuditMetadata(),
    )

    bb_platform.post_summary(result)
    assert post_route.called
    posted_json = post_route.calls.last.request.read().decode("utf-8")
    assert "<!-- gatekeeper-summary-marker -->" in posted_json
    assert "PASS" in posted_json


@respx.mock
def test_bitbucket_update_existing_summary_comment(bb_platform: BitbucketPlatform) -> None:
    comments_url = f"{BITBUCKET_API_BASE}/repositories/my-team/sample-repo/pullrequests/42/comments"
    existing_comment = {
        "id": 999,
        "content": {"raw": "Old report\n<!-- gatekeeper-summary-marker -->"},
    }
    respx.get(comments_url).mock(
        return_value=httpx.Response(200, json={"values": [existing_comment]})
    )

    update_route = respx.put(f"{comments_url}/999").mock(
        return_value=httpx.Response(200, json={"id": 999})
    )

    result = AuditResult(
        verdict=Verdict.FAIL,
        findings=[],
        summary=AuditSummary(),
        metadata=AuditMetadata(),
    )

    bb_platform.post_summary(result)
    assert update_route.called
    updated_json = update_route.calls.last.request.read().decode("utf-8")
    assert "FAIL" in updated_json


@respx.mock
def test_bitbucket_post_inline_comments(bb_platform: BitbucketPlatform) -> None:
    comments_url = f"{BITBUCKET_API_BASE}/repositories/my-team/sample-repo/pullrequests/42/comments"
    post_route = respx.post(comments_url).mock(return_value=httpx.Response(201, json={"id": 2001}))

    f = Finding.create(
        file="src/app.py",
        start_line=15,
        end_line=15,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        category=Category.INJECTION,
        title="SQL Injection",
        explanation="Direct string concat",
        suggested_fix="Param query",
    )
    result = AuditResult(
        verdict=Verdict.FAIL,
        findings=[f],
        summary=AuditSummary.from_findings([f]),
        metadata=AuditMetadata(),
    )

    bb_platform.post_inline_comments(result, max_inline=10)
    assert post_route.called
    posted_data = post_route.calls.last.request.read().decode("utf-8")
    assert "src/app.py" in posted_data
    assert "SQL Injection" in posted_data


@respx.mock
def test_bitbucket_code_insights_report_and_annotations(bb_platform: BitbucketPlatform) -> None:
    report_url = f"{BITBUCKET_API_BASE}/repositories/my-team/sample-repo/commit/a1b2c3d4e5f6/reports/gatekeeper-ai"
    annotations_url = f"{report_url}/annotations"

    report_route = respx.put(report_url).mock(
        return_value=httpx.Response(200, json={"key": "gatekeeper-ai"})
    )
    annotations_route = respx.post(annotations_url).mock(return_value=httpx.Response(200, json=[]))

    f = Finding.create(
        file="src/app.py",
        start_line=20,
        end_line=20,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SECRES,
        title="Hardcoded Secret",
        explanation="Found API token",
        suggested_fix="Move to env",
    )
    result = AuditResult(
        verdict=Verdict.FAIL,
        findings=[f],
        summary=AuditSummary.from_findings([f]),
        metadata=AuditMetadata(),
    )

    bb_platform.set_status(result)

    assert report_route.called
    report_data = json.loads(report_route.calls.last.request.read().decode("utf-8"))
    assert report_data["result"] == "FAILED"

    assert annotations_route.called
    annotations_data = json.loads(annotations_route.calls.last.request.read().decode("utf-8"))
    assert len(annotations_data) == 1
    assert annotations_data[0]["title"] == "Hardcoded Secret"
    assert annotations_data[0]["severity"] == "HIGH"


@respx.mock
def test_bitbucket_audit_flow_fails_planted_issues(tmp_path: Path) -> None:
    """Verify that a Bitbucket PR with planted vulnerabilities receives FAILED status."""
    vulnerable_code = (Path(__file__).parent / "fixtures" / "vulnerable" / "app.py").read_text(
        encoding="utf-8"
    )
    diff_text = f"""diff --git a/app.py b/app.py
new file mode 100644
--- /dev/null
+++ b/app.py
@@ -0,0 +1,{len(vulnerable_code.splitlines())} @@
""" + "\n".join(f"+{line}" for line in vulnerable_code.splitlines())

    respx.get(f"{BITBUCKET_API_BASE}/repositories/my-team/sample-repo/pullrequests/42/diff").mock(
        return_value=httpx.Response(200, text=diff_text)
    )
    comments_url = f"{BITBUCKET_API_BASE}/repositories/my-team/sample-repo/pullrequests/42/comments"
    respx.get(comments_url).mock(return_value=httpx.Response(200, json={"values": []}))
    respx.post(comments_url).mock(return_value=httpx.Response(201, json={"id": 1}))

    report_url = f"{BITBUCKET_API_BASE}/repositories/my-team/sample-repo/commit/a1b2c3d4e5f6/reports/gatekeeper-ai"
    report_route = respx.put(report_url).mock(
        return_value=httpx.Response(200, json={"key": "gatekeeper-ai"})
    )
    respx.post(f"{report_url}/annotations").mock(return_value=httpx.Response(200, json=[]))

    platform = BitbucketPlatform(
        token="token",
        workspace="my-team",
        repo_slug="sample-repo",
        pr_id="42",
        commit="a1b2c3d4e5f6",
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
    assert report_route.called
    report_data = json.loads(report_route.calls.last.request.read().decode("utf-8"))
    assert report_data["result"] == "FAILED"


@respx.mock
def test_bitbucket_audit_flow_passes_clean_code(tmp_path: Path) -> None:
    """Verify that a Bitbucket PR with clean code receives PASSED status."""
    clean_code = (Path(__file__).parent / "fixtures" / "clean" / "app.py").read_text(
        encoding="utf-8"
    )
    diff_text = f"""diff --git a/app.py b/app.py
new file mode 100644
--- /dev/null
+++ b/app.py
@@ -0,0 +1,{len(clean_code.splitlines())} @@
""" + "\n".join(f"+{line}" for line in clean_code.splitlines())

    respx.get(f"{BITBUCKET_API_BASE}/repositories/my-team/sample-repo/pullrequests/42/diff").mock(
        return_value=httpx.Response(200, text=diff_text)
    )
    comments_url = f"{BITBUCKET_API_BASE}/repositories/my-team/sample-repo/pullrequests/42/comments"
    respx.get(comments_url).mock(return_value=httpx.Response(200, json={"values": []}))
    respx.post(comments_url).mock(return_value=httpx.Response(201, json={"id": 1}))

    report_url = f"{BITBUCKET_API_BASE}/repositories/my-team/sample-repo/commit/a1b2c3d4e5f6/reports/gatekeeper-ai"
    report_route = respx.put(report_url).mock(
        return_value=httpx.Response(200, json={"key": "gatekeeper-ai"})
    )

    platform = BitbucketPlatform(
        token="token",
        workspace="my-team",
        repo_slug="sample-repo",
        pr_id="42",
        commit="a1b2c3d4e5f6",
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
    assert report_route.called
    report_data = json.loads(report_route.calls.last.request.read().decode("utf-8"))
    assert report_data["result"] == "PASSED"
