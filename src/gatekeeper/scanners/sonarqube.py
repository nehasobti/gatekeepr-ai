"""SonarQube / SonarCloud Web API scanner runner."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import httpx

from gatekeeper.config import SonarQubeConfig
from gatekeeper.models import Category, Confidence, Finding, Severity
from gatekeeper.scanners.base import BaseScanner

logger = logging.getLogger("gatekeeper.scanners.sonarqube")


class SonarQubeScanner(BaseScanner):
    """Integrates SonarQube / SonarCloud issues via REST API."""

    def __init__(self, config: SonarQubeConfig, pr_id: str | None = None) -> None:
        self.config = config
        self.pr_id = pr_id

    @property
    def name(self) -> str:
        return "sonarqube"

    def is_available(self) -> bool:
        url = os.environ.get(self.config.url_env)
        token = os.environ.get(self.config.token_env)
        return bool(self.config.enabled and url and token and self.config.project_key)

    def scan(
        self,
        changed_files: list[str],  # noqa: ARG002
        repo_root: Path,  # noqa: ARG002
        diff_text: str | None = None,  # noqa: ARG002
    ) -> list[Finding]:
        if not self.config.enabled:
            return []

        host_url = os.environ.get(self.config.url_env)
        token = os.environ.get(self.config.token_env)

        if not host_url or not token:
            logger.warning("SonarQube credentials missing in environment variables.")
            return []

        if not self.config.project_key:
            logger.warning("SonarQube project_key is not configured.")
            return []

        base_url = host_url.rstrip("/")
        params: dict[str, Any] = {
            "componentKeys": self.config.project_key,
            "resolved": "false",
            "ps": 100,
        }
        if self.pr_id:
            params["pullRequest"] = self.pr_id

        try:
            with httpx.Client(timeout=15.0) as client:
                resp = client.get(
                    f"{base_url}/api/issues/search",
                    params=params,
                    auth=(token, ""),
                )
                if resp.status_code >= 400:
                    logger.warning(f"SonarQube API returned {resp.status_code}: {resp.text[:200]}")
                    return []
                data = resp.json()
                return self._parse_issues(data)
        except Exception as e:
            logger.error(f"Error connecting to SonarQube: {e}")
            return []

    def _parse_issues(self, data: dict[str, Any]) -> list[Finding]:
        issues = data.get("issues", [])
        findings: list[Finding] = []

        for issue in issues:
            key = issue.get("key", "sonar")
            rule = issue.get("rule", "sonar-issue")
            message = issue.get("message", "SonarQube issue detected.")
            component = issue.get("component", "")

            # Strip project key prefix from component, e.g. "my-project:src/app.py" -> "src/app.py"
            file_rel = component.split(":", 1)[1] if ":" in component else component

            line = issue.get("line")
            if not line:
                text_range = issue.get("textRange", {})
                line = text_range.get("startLine", 1)

            # Severity mapping
            raw_sev = issue.get("severity", "MAJOR").upper()
            if raw_sev == "BLOCKER":
                severity = Severity.CRITICAL
            elif raw_sev == "CRITICAL":
                severity = Severity.HIGH
            elif raw_sev == "MAJOR":
                severity = Severity.MEDIUM
            elif raw_sev == "MINOR":
                severity = Severity.LOW
            else:
                severity = Severity.INFO

            # Category mapping
            issue_type = issue.get("type", "CODE_SMELL").upper()
            if issue_type == "VULNERABILITY":
                category = Category.INJECTION
            elif issue_type == "SECURITY_HOTSPOT":
                category = Category.AUTH
            elif issue_type == "BUG":
                category = Category.BUG
            else:
                category = Category.MAINTAINABILITY

            findings.append(
                Finding(
                    id=Finding.compute_fingerprint(
                        rule=rule,
                        file=file_rel,
                        snippet=f"{line}:{key}",
                    ),
                    file=file_rel,
                    start_line=int(line),
                    end_line=int(line),
                    severity=severity,
                    confidence=Confidence.HIGH,
                    category=category,
                    owasp=None,
                    cwe=None,
                    title=f"SonarQube: {rule}"[:100],
                    explanation=message,
                    suggested_fix="Address the issue reported by SonarQube.",
                    source=["sonarqube"],
                )
            )

        return findings
