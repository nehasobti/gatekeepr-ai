"""Tests for static analysis scanners (Semgrep, Bandit, Gitleaks, SonarQube)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

from gatekeeper.config import (
    BanditConfig,
    GitleaksConfig,
    ScannersConfig,
    SemgrepConfig,
    SonarQubeConfig,
)
from gatekeeper.models import Category, Confidence, Finding, Severity
from gatekeeper.scanners import (
    BanditScanner,
    BaseScanner,
    GitleaksScanner,
    SemgrepScanner,
    SonarQubeScanner,
    run_all_scanners,
)


class DummyScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "dummy"

    def is_available(self) -> bool:
        return True

    def scan(
        self,
        changed_files: list[str],  # noqa: ARG002
        repo_root: Path,  # noqa: ARG002
        diff_text: str | None = None,  # noqa: ARG002
    ) -> list[Finding]:
        return []


def test_base_scanner_filter_to_changed_lines() -> None:
    scanner = DummyScanner()
    f1 = Finding.create(
        file="src/app.py",
        start_line=10,
        end_line=12,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.INJECTION,
        title="SQL injection",
        explanation="Untrusted query",
        suggested_fix="Parametrize",
    )
    f2 = Finding.create(
        file="src/app.py",
        start_line=50,
        end_line=50,
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        category=Category.BUG,
        title="Minor issue",
        explanation="Explanation",
        suggested_fix="Fix",
    )
    f3 = Finding.create(
        file="src/other.py",
        start_line=1,
        end_line=1,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category=Category.AUTH,
        title="Auth issue",
        explanation="Explanation",
        suggested_fix="Fix",
    )

    changed_lines = {
        "src/app.py": {11, 15},  # overlaps f1 (lines 10-12)
        "src/other.py": {100},  # does not overlap f3 (line 1)
    }

    filtered = scanner.filter_to_changed_lines([f1, f2, f3], changed_lines)
    assert len(filtered) == 1
    assert filtered[0].id == f1.id


def test_semgrep_scanner_disabled_or_unavailable(tmp_path: Path) -> None:
    cfg = SemgrepConfig(enabled=False)
    scanner = SemgrepScanner(cfg)
    assert scanner.scan(["app.py"], tmp_path) == []

    cfg_enabled = SemgrepConfig(enabled=True)
    scanner_enabled = SemgrepScanner(cfg_enabled)
    with patch("shutil.which", return_value=None):
        assert scanner_enabled.scan(["app.py"], tmp_path) == []


def test_semgrep_scanner_mock_execution(tmp_path: Path) -> None:
    sample_file = tmp_path / "app.py"
    sample_file.write_text("print('hello')", encoding="utf-8")

    cfg = SemgrepConfig(enabled=True, config="p/owasp-top-ten")
    scanner = SemgrepScanner(cfg)

    semgrep_json = {
        "results": [
            {
                "check_id": "python.lang.security.insecure-hash.md5",
                "path": str(sample_file),
                "start": {"line": 5, "col": 1},
                "end": {"line": 5, "col": 20},
                "extra": {
                    "message": "Use of weak hash MD5",
                    "severity": "ERROR",
                    "metadata": {
                        "cwe": ["CWE-327"],
                        "owasp": ["A02:2021 Cryptographic Failures"],
                        "category": "security",
                    },
                    "fix": "Use SHA-256",
                },
            }
        ]
    }

    mock_process = MagicMock()
    mock_process.stdout = json.dumps(semgrep_json)
    mock_process.stderr = ""

    with (
        patch("shutil.which", return_value="/usr/bin/semgrep"),
        patch("subprocess.run", return_value=mock_process),
    ):
        findings = scanner.scan(["app.py"], tmp_path)
        assert len(findings) == 1
        f = findings[0]
        assert f.source == ["semgrep"]
        assert f.severity == Severity.HIGH
        assert f.category == Category.CRYPTO
        assert f.cwe == "CWE-327"
        assert f.start_line == 5


def test_semgrep_categories_infer() -> None:
    assert SemgrepScanner._infer_category("rule.sql.injection", {}) == Category.INJECTION
    assert SemgrepScanner._infer_category("rule.xss.dom", {}) == Category.XSS
    assert SemgrepScanner._infer_category("rule.hardcoded.secret", {}) == Category.SECRETS
    assert SemgrepScanner._infer_category("rule.auth.jwt", {}) == Category.AUTH
    assert SemgrepScanner._infer_category("rule.ssrf.request", {}) == Category.SSRF
    assert (
        SemgrepScanner._infer_category("rule.deserialization.pickle", {})
        == Category.DESERIALIZATION
    )
    assert SemgrepScanner._infer_category("rule.access.control", {}) == Category.ACCESS_CONTROL
    assert (
        SemgrepScanner._infer_category("rule.slow.perf", {"category": "performance"})
        == Category.PERFORMANCE
    )
    assert SemgrepScanner._infer_category("other.misc", {}) == Category.BUG


def test_bandit_scanner_auto_and_execution(tmp_path: Path) -> None:
    py_file = tmp_path / "main.py"
    py_file.write_text("import pickle; pickle.loads(b'')", encoding="utf-8")

    cfg = BanditConfig(enabled="auto")
    scanner = BanditScanner(cfg)

    # When no python files changed
    assert scanner.scan(["README.md"], tmp_path) == []

    bandit_json = {
        "results": [
            {
                "code": "pickle.loads()",
                "filename": str(py_file),
                "issue_confidence": "HIGH",
                "issue_cwe": {"id": 502},
                "issue_severity": "HIGH",
                "issue_text": "Pickle and modules that wrap it can be unsafe when used on untrusted data.",
                "line_number": 1,
                "line_range": [1],
                "test_id": "B301",
                "test_name": "pickle",
            }
        ]
    }

    mock_proc = MagicMock()
    mock_proc.stdout = json.dumps(bandit_json)
    mock_proc.stderr = ""

    with (
        patch("shutil.which", return_value="/usr/bin/bandit"),
        patch("subprocess.run", return_value=mock_proc),
    ):
        findings = scanner.scan(["main.py"], tmp_path)
        assert len(findings) == 1
        f = findings[0]
        assert f.source == ["bandit"]
        assert f.severity == Severity.HIGH
        assert f.category == Category.DESERIALIZATION
        assert f.cwe == "CWE-502"


def test_bandit_categories_infer() -> None:
    assert BanditScanner._infer_category("B608", "sql injection") == Category.INJECTION
    assert BanditScanner._infer_category("B105", "hardcoded password") == Category.SECRETS
    assert BanditScanner._infer_category("B324", "hash md5") == Category.CRYPTO
    assert BanditScanner._infer_category("B701", "jinja2 xss") == Category.XSS
    assert BanditScanner._infer_category("B999", "generic") == Category.BUG


def test_gitleaks_fallback_scanner(tmp_path: Path) -> None:
    sec_file = tmp_path / "secrets.py"
    sec_file.write_text("AWS_KEY = 'AKIA1234567890123456'\n", encoding="utf-8")

    cfg = GitleaksConfig(enabled=True)
    scanner = GitleaksScanner(cfg)

    with patch("shutil.which", return_value=None):
        findings = scanner.scan(["secrets.py"], tmp_path)
        assert len(findings) == 1
        assert findings[0].source == ["gitleaks"]
        assert findings[0].category == Category.SECRETS
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].start_line == 1


def test_gitleaks_cli_scanner(tmp_path: Path) -> None:
    sec_file = tmp_path / "token.py"
    sec_file.write_text("token = 'test'", encoding="utf-8")

    cfg = GitleaksConfig(enabled=True)
    scanner = GitleaksScanner(cfg)

    gitleaks_payload = [
        {
            "Description": "GitHub Token",
            "StartLine": 1,
            "EndLine": 1,
            "File": str(sec_file),
            "Secret": "ghp_12345",
            "RuleID": "github-pat",
        }
    ]

    def mock_subprocess_run(cmd: list[str], **kwargs: object) -> MagicMock:  # noqa: ARG001
        report_path_idx = cmd.index("--report-path") + 1
        report_file = Path(cmd[report_path_idx])
        report_file.write_text(json.dumps(gitleaks_payload), encoding="utf-8")
        proc = MagicMock()
        proc.returncode = 1
        return proc

    with (
        patch("shutil.which", return_value="/usr/bin/gitleaks"),
        patch("subprocess.run", side_effect=mock_subprocess_run),
    ):
        findings = scanner.scan(["token.py"], tmp_path)
        assert len(findings) == 1
        assert findings[0].source == ["gitleaks"]
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].category == Category.SECRETS


@respx.mock
def test_sonarqube_scanner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SONAR_HOST_URL", "https://sonar.example.com")
    monkeypatch.setenv("SONAR_TOKEN", "sqp_token123")

    cfg = SonarQubeConfig(
        enabled=True,
        url_env="SONAR_HOST_URL",
        token_env="SONAR_TOKEN",
        project_key="my_repo",
    )
    scanner = SonarQubeScanner(cfg, pr_id="12")
    assert scanner.is_available()

    sonar_response = {
        "issues": [
            {
                "key": "ISSUE_101",
                "rule": "python:S2077",
                "severity": "BLOCKER",
                "component": "my_repo:src/db.py",
                "line": 14,
                "message": "SQL queries should not be vulnerable to injection.",
                "type": "VULNERABILITY",
            },
            {
                "key": "ISSUE_102",
                "rule": "python:S100",
                "severity": "MINOR",
                "component": "my_repo:src/db.py",
                "line": 20,
                "message": "Rename method.",
                "type": "CODE_SMELL",
            },
        ]
    }

    respx.get("https://sonar.example.com/api/issues/search").mock(
        return_value=httpx.Response(200, json=sonar_response)
    )

    findings = scanner.scan(["src/db.py"], tmp_path)
    assert len(findings) == 2
    f = findings[0]
    assert f.source == ["sonarqube"]
    assert f.severity == Severity.CRITICAL
    assert f.file == "src/db.py"
    assert f.start_line == 14
    assert findings[1].category == Category.MAINTAINABILITY


def test_sonarqube_missing_env(tmp_path: Path) -> None:
    cfg = SonarQubeConfig(enabled=True, project_key="proj")
    scanner = SonarQubeScanner(cfg)
    assert scanner.scan(["app.py"], tmp_path) == []


def test_run_all_scanners_orchestration(tmp_path: Path) -> None:
    f_py = tmp_path / "app.py"
    f_py.write_text("ghp_123456789012345678901234567890123456\n", encoding="utf-8")

    cfg = ScannersConfig(
        semgrep=SemgrepConfig(enabled=False),
        bandit=BanditConfig(enabled=False),
        gitleaks=GitleaksConfig(enabled=True),
        sonarqube=SonarQubeConfig(enabled=False),
    )

    findings = run_all_scanners(
        config=cfg,
        changed_files=["app.py"],
        repo_root=tmp_path,
        changed_lines_by_file={"app.py": {1}},
    )
    assert len(findings) >= 1
    assert any(f.source == ["gitleaks"] for f in findings)
