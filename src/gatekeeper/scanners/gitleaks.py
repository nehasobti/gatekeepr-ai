"""Gitleaks secret scanner runner."""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from gatekeeper.config import GitleaksConfig
from gatekeeper.models import Category, Confidence, Finding, Severity
from gatekeeper.scanners.base import BaseScanner

logger = logging.getLogger("gatekeeper.scanners.gitleaks")

FALLBACK_SECRET_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "aws-access-key-id",
        "AWS Access Key ID",
        re.compile(r"\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"),
    ),
    (
        "github-pat",
        "GitHub Personal Access Token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b"),
    ),
    (
        "slack-token",
        "Slack Token",
        re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}\b"),
    ),
    (
        "slack-webhook",
        "Slack Incoming Webhook",
        re.compile(
            r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"
        ),
    ),
    (
        "private-key",
        "Private Cryptographic Key",
        re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----"),
    ),
    (
        "generic-api-secret",
        "Hardcoded API Secret",
        re.compile(
            r"""(?i)(?:api[_-]?key|secret|password|access[_-]?token)\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"]"""
        ),
    ),
]


class GitleaksScanner(BaseScanner):
    """Runner for Gitleaks secret detection."""

    def __init__(self, config: GitleaksConfig) -> None:
        self.config = config

    @property
    def name(self) -> str:
        return "gitleaks"

    def is_available(self) -> bool:
        return True

    def scan(
        self,
        changed_files: list[str],
        repo_root: Path,
        diff_text: str | None = None,  # noqa: ARG002
    ) -> list[Finding]:
        if not self.config.enabled:
            return []

        if shutil.which("gitleaks") is not None:
            return self._scan_with_cli(changed_files, repo_root)

        return self._scan_with_fallback(changed_files, repo_root)

    def _scan_with_cli(self, changed_files: list[str], repo_root: Path) -> list[Finding]:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            cmd = [
                "gitleaks",
                "detect",
                "--no-git",
                "--report-format",
                "json",
                "--report-path",
                str(tmp_path),
                "--source",
                str(repo_root),
            ]
            subprocess.run(cmd, cwd=str(repo_root), capture_output=True, text=True, check=False)

            if not tmp_path.exists() or tmp_path.stat().st_size == 0:
                return []

            content = tmp_path.read_text(encoding="utf-8")
            return self._parse_gitleaks_json(content, repo_root)
        except Exception as e:
            logger.warning(f"Gitleaks CLI error: {e}, falling back to built-in rules")
            return self._scan_with_fallback(changed_files, repo_root)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def _parse_gitleaks_json(self, raw_json: str, repo_root: Path) -> list[Finding]:
        try:
            items = json.loads(raw_json)
        except Exception:
            return []

        findings: list[Finding] = []
        for item in items:
            rule_id = item.get("RuleID", "gitleaks-secret")
            desc = item.get("Description", "Detected hardcoded secret")
            file_path = item.get("File", "")
            try:
                rel_path = Path(file_path).relative_to(repo_root).as_posix()
            except ValueError:
                rel_path = Path(file_path).as_posix()

            start_line = item.get("StartLine", 1)
            end_line = item.get("EndLine", start_line)

            findings.append(
                Finding(
                    id=Finding.compute_fingerprint(
                        rule=rule_id,
                        file=rel_path,
                        snippet=f"{start_line}:{rule_id}",
                    ),
                    file=rel_path,
                    start_line=start_line,
                    end_line=end_line,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    category=Category.SECRETS,
                    owasp="A07:2021 Identification and Authentication Failures",
                    cwe="CWE-798",
                    title=f"Hardcoded Secret: {desc}"[:100],
                    explanation=f"Gitleaks identified a credential ({desc}) hardcoded in source code.",
                    suggested_fix="Revoke this credential immediately and store secrets in environment variables.",
                    source=["gitleaks"],
                )
            )
        return findings

    def _scan_with_fallback(self, changed_files: list[str], repo_root: Path) -> list[Finding]:
        findings: list[Finding] = []

        for rel_file in changed_files:
            file_path = repo_root / rel_file
            if not file_path.is_file():
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            lines = content.splitlines()
            for line_idx, line in enumerate(lines, start=1):
                for rule_id, desc, pattern in FALLBACK_SECRET_PATTERNS:
                    if pattern.search(line):
                        findings.append(
                            Finding(
                                id=Finding.compute_fingerprint(
                                    rule=rule_id,
                                    file=rel_file.replace("\\", "/"),
                                    snippet=f"{line_idx}:{rule_id}",
                                ),
                                file=rel_file.replace("\\", "/"),
                                start_line=line_idx,
                                end_line=line_idx,
                                severity=Severity.CRITICAL,
                                confidence=Confidence.HIGH,
                                category=Category.SECRETS,
                                owasp="A07:2021 Identification and Authentication Failures",
                                cwe="CWE-798",
                                title=f"Hardcoded Secret: {desc}"[:100],
                                explanation=f"Detected sensitive credential pattern ({desc}) committed in source code.",
                                suggested_fix="Revoke credential immediately and load it from environment variables.",
                                source=["gitleaks"],
                            )
                        )
                        break

        return findings
