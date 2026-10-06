"""Semgrep static analysis scanner runner."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from gatekeeper.config import SemgrepConfig
from gatekeeper.models import Category, Confidence, Finding, Severity
from gatekeeper.scanners.base import BaseScanner

logger = logging.getLogger("gatekeeper.scanners.semgrep")


class SemgrepScanner(BaseScanner):
    """Runner for Semgrep SAST scans."""

    def __init__(self, config: SemgrepConfig) -> None:
        self.config = config

    @property
    def name(self) -> str:
        return "semgrep"

    def is_available(self) -> bool:
        return shutil.which("semgrep") is not None

    def scan(
        self,
        changed_files: list[str],
        repo_root: Path,
        diff_text: str | None = None,  # noqa: ARG002
    ) -> list[Finding]:
        if not self.config.enabled:
            return []

        if not self.is_available():
            logger.warning("Semgrep executable not found in PATH. Skipping Semgrep scan.")
            return []

        # Filter existing files relative to repo_root
        target_files = [f for f in changed_files if (repo_root / f).is_file()]
        if not target_files:
            return []

        cmd = [
            "semgrep",
            "scan",
            "--config",
            self.config.config,
            "--json",
            "--quiet",
            *target_files,
        ]

        env = os.environ.copy()
        if "SEMGREP_APP_TOKEN" in os.environ:
            env["SEMGREP_APP_TOKEN"] = os.environ["SEMGREP_APP_TOKEN"]

        try:
            result = subprocess.run(
                cmd,
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )
            raw_output = result.stdout
            if not raw_output.strip() and result.stderr:
                logger.warning(f"Semgrep stderr: {result.stderr}")
                return []
            return self._parse_json_output(raw_output, repo_root)
        except Exception as e:
            logger.error(f"Error running Semgrep: {e}")
            return []

    def _parse_json_output(self, raw_json: str, repo_root: Path) -> list[Finding]:
        try:
            data = json.loads(raw_json)
        except Exception as e:
            logger.warning(f"Failed to parse Semgrep JSON output: {e}")
            return []

        findings: list[Finding] = []
        results = data.get("results", [])

        for r in results:
            path_str = r.get("path", "")
            try:
                rel_path = Path(path_str).relative_to(repo_root).as_posix()
            except ValueError:
                rel_path = Path(path_str).as_posix()

            start_line = r.get("start", {}).get("line", 1)
            end_line = r.get("end", {}).get("line", start_line)

            extra: dict[str, Any] = r.get("extra", {})
            metadata: dict[str, Any] = extra.get("metadata", {})
            check_id = r.get("check_id", "semgrep-finding")

            message = extra.get("message", "Semgrep detected a potential security issue.")
            fix = extra.get("fix", "")

            # Severity mapping
            raw_sev = extra.get("severity", "WARNING").upper()
            if raw_sev == "ERROR":
                severity = Severity.HIGH
            elif raw_sev == "INFO":
                severity = Severity.LOW
            else:
                severity = Severity.MEDIUM

            # Category mapping
            category = self._infer_category(check_id, metadata)

            # CWE and OWASP extraction
            cwe_raw = metadata.get("cwe", [])
            cwe_str = ", ".join(cwe_raw) if isinstance(cwe_raw, list) else str(cwe_raw or "")

            owasp_raw = metadata.get("owasp", [])
            owasp_str = (
                ", ".join(owasp_raw) if isinstance(owasp_raw, list) else str(owasp_raw or "")
            )

            title = check_id.split(".")[-1].replace("-", " ").title()[:100]

            findings.append(
                Finding(
                    id=Finding.compute_fingerprint(
                        rule=check_id,
                        file=rel_path,
                        snippet=f"{start_line}:{message}",
                    ),
                    file=rel_path,
                    start_line=start_line,
                    end_line=end_line,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    category=category,
                    owasp=owasp_str or None,
                    cwe=cwe_str or None,
                    title=title,
                    explanation=message,
                    suggested_fix=fix
                    or "Refactor the flagged code following security best practices.",
                    source=["semgrep"],
                )
            )

        return findings

    @staticmethod
    def _infer_category(check_id: str, metadata: dict[str, Any]) -> Category:
        lower_id = check_id.lower()
        cat_meta = str(metadata.get("category", "")).lower()

        if "sql" in lower_id or "injection" in lower_id or "commandi" in lower_id:
            return Category.INJECTION
        if "xss" in lower_id or "cross-site-scripting" in lower_id:
            return Category.XSS
        if "secret" in lower_id or "token" in lower_id or "password" in lower_id:
            return Category.SECRETS
        if "auth" in lower_id or "jwt" in lower_id or "permission" in lower_id:
            return Category.AUTH
        if "crypto" in lower_id or "cipher" in lower_id or "hash" in lower_id:
            return Category.CRYPTO
        if "ssrf" in lower_id:
            return Category.SSRF
        if "deserial" in lower_id or "pickle" in lower_id:
            return Category.DESERIALIZATION
        if "access" in lower_id or "cors" in lower_id:
            return Category.ACCESS_CONTROL
        if "perf" in cat_meta or "performance" in lower_id:
            return Category.PERFORMANCE
        return Category.BUG
