"""Bandit static analysis scanner runner for Python code."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

from gatekeeper.config import BanditConfig
from gatekeeper.models import Category, Confidence, Finding, Severity
from gatekeeper.scanners.base import BaseScanner

logger = logging.getLogger("gatekeeper.scanners.bandit")


class BanditScanner(BaseScanner):
    """Runner for Bandit Python SAST scans."""

    def __init__(self, config: BanditConfig) -> None:
        self.config = config

    @property
    def name(self) -> str:
        return "bandit"

    def is_available(self) -> bool:
        return shutil.which("bandit") is not None

    def scan(
        self,
        changed_files: list[str],
        repo_root: Path,
        diff_text: str | None = None,  # noqa: ARG002
    ) -> list[Finding]:
        if not self.config.enabled:
            return []

        # Find existing python files
        py_files = [f for f in changed_files if f.endswith(".py") and (repo_root / f).is_file()]

        if not py_files:
            return []

        if not self.is_available():
            logger.warning("Bandit executable not found in PATH. Skipping Bandit scan.")
            return []

        cmd = [
            "bandit",
            "-f",
            "json",
            "-q",
            *py_files,
        ]

        try:
            result = subprocess.run(
                cmd,
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                check=False,
            )
            raw_output = result.stdout
            if not raw_output.strip() and result.stderr:
                logger.warning(f"Bandit stderr: {result.stderr}")
                return []
            return self._parse_json_output(raw_output, repo_root)
        except Exception as e:
            logger.error(f"Error running Bandit: {e}")
            return []

    def _parse_json_output(self, raw_json: str, repo_root: Path) -> list[Finding]:
        try:
            data = json.loads(raw_json)
        except Exception as e:
            logger.warning(f"Failed to parse Bandit JSON output: {e}")
            return []

        findings: list[Finding] = []
        results = data.get("results", [])

        for r in results:
            filename = r.get("filename", "")
            try:
                rel_path = Path(filename).relative_to(repo_root).as_posix()
            except ValueError:
                rel_path = Path(filename).as_posix()

            start_line = r.get("line_number", 1)
            line_range = r.get("line_range", [start_line])
            end_line = max(line_range) if line_range else start_line

            test_id = r.get("test_id", "bandit")
            test_name = r.get("test_name", "security issue")
            issue_text = r.get("issue_text", "")

            # Severity mapping
            sev_str = r.get("issue_severity", "MEDIUM").upper()
            if sev_str == "HIGH":
                severity = Severity.HIGH
            elif sev_str == "LOW":
                severity = Severity.LOW
            else:
                severity = Severity.MEDIUM

            # Confidence mapping
            conf_str = r.get("issue_confidence", "MEDIUM").upper()
            if conf_str == "HIGH":
                confidence = Confidence.HIGH
            elif conf_str == "LOW":
                confidence = Confidence.LOW
            else:
                confidence = Confidence.MEDIUM

            category = self._infer_category(test_id, issue_text)

            cwe_obj: dict[str, Any] = r.get("issue_cwe", {})
            cwe_id = cwe_obj.get("id")
            cwe_str = f"CWE-{cwe_id}" if cwe_id else None

            title = f"{test_id}: {test_name.replace('_', ' ').title()}"[:100]

            findings.append(
                Finding(
                    id=Finding.compute_fingerprint(
                        rule=test_id,
                        file=rel_path,
                        snippet=f"{start_line}:{issue_text}",
                    ),
                    file=rel_path,
                    start_line=start_line,
                    end_line=end_line,
                    severity=severity,
                    confidence=confidence,
                    category=category,
                    owasp=None,
                    cwe=cwe_str,
                    title=title,
                    explanation=issue_text,
                    suggested_fix="Review and remediate according to Bandit guidelines.",
                    source=["bandit"],
                )
            )

        return findings

    @staticmethod
    def _infer_category(test_id: str, issue_text: str) -> Category:
        tid = test_id.upper()
        text = issue_text.lower()

        if (
            tid in ("B608", "B601", "B602", "B603", "B604", "B605", "B606", "B607", "B609")
            or "injection" in text
            or "sql" in text
        ):
            return Category.INJECTION
        if (
            tid in ("B105", "B106", "B107")
            or "password" in text
            or "secret" in text
            or "token" in text
        ):
            return Category.SECRETS
        if tid in ("B301", "B302", "B403") or "pickle" in text or "deserial" in text:
            return Category.DESERIALIZATION
        if (
            tid in ("B303", "B324", "B501", "B502", "B503", "B504", "B505")
            or "hash" in text
            or "cipher" in text
            or "md5" in text
        ):
            return Category.CRYPTO
        if tid in ("B201", "B701", "B702", "B703") or "xss" in text or "jinja" in text:
            return Category.XSS
        return Category.BUG
