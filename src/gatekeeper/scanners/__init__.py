"""Static analysis scanners orchestration."""

from __future__ import annotations

import logging
from pathlib import Path

from gatekeeper.config import ScannersConfig
from gatekeeper.models import Finding
from gatekeeper.scanners.bandit import BanditScanner
from gatekeeper.scanners.base import BaseScanner
from gatekeeper.scanners.gitleaks import GitleaksScanner
from gatekeeper.scanners.semgrep import SemgrepScanner
from gatekeeper.scanners.sonarqube import SonarQubeScanner

logger = logging.getLogger("gatekeeper.scanners")

__all__ = [
    "BanditScanner",
    "BaseScanner",
    "GitleaksScanner",
    "SemgrepScanner",
    "SonarQubeScanner",
    "run_all_scanners",
]


def run_all_scanners(
    config: ScannersConfig,
    changed_files: list[str],
    repo_root: Path,
    changed_lines_by_file: dict[str, set[int]],
    pr_id: str | None = None,
) -> list[Finding]:
    """Execute all enabled static scanners and return findings on changed lines."""
    scanners: list[BaseScanner] = []

    if config.semgrep.enabled:
        scanners.append(SemgrepScanner(config.semgrep))

    # Bandit enabled can be True or 'auto'
    if config.bandit.enabled is True or (
        config.bandit.enabled == "auto" and any(f.endswith(".py") for f in changed_files)
    ):
        scanners.append(BanditScanner(config.bandit))

    if config.gitleaks.enabled:
        scanners.append(GitleaksScanner(config.gitleaks))

    if config.sonarqube.enabled:
        scanners.append(SonarQubeScanner(config.sonarqube, pr_id=pr_id))

    all_findings: list[Finding] = []

    for scanner in scanners:
        try:
            logger.info(f"Running scanner: {scanner.name}")
            raw_findings = scanner.scan(changed_files=changed_files, repo_root=repo_root)
            line_filtered = scanner.filter_to_changed_lines(
                findings=raw_findings,
                changed_lines_by_file=changed_lines_by_file,
            )
            logger.info(
                f"Scanner {scanner.name} returned {len(raw_findings)} findings ({len(line_filtered)} on changed lines)"
            )
            all_findings.extend(line_filtered)
        except Exception as e:
            logger.error(f"Error during execution of scanner {scanner.name}: {e}")

    return all_findings
