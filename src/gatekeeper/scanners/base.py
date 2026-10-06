"""Base interface for static analysis scanners."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from gatekeeper.models import Finding


class BaseScanner(ABC):
    """Abstract base class for static analysis tool scanners."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the scanner (e.g. 'semgrep', 'bandit', 'gitleaks', 'sonarqube')."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if scanner dependencies (CLI tool or configuration) are available."""
        ...

    @abstractmethod
    def scan(
        self,
        changed_files: list[str],
        repo_root: Path,
        diff_text: str | None = None,
    ) -> list[Finding]:
        """Execute scanner on changed files and return raw findings."""
        ...

    def filter_to_changed_lines(
        self,
        findings: list[Finding],
        changed_lines_by_file: dict[str, set[int]],
    ) -> list[Finding]:
        """Retain only findings that intersect with changed lines in the diff."""
        filtered: list[Finding] = []
        for f in findings:
            valid_lines = changed_lines_by_file.get(f.file)
            if not valid_lines:
                # Normalize path comparison (e.g. forward slashes)
                norm_file = f.file.replace("\\", "/")
                for path_k, lines_v in changed_lines_by_file.items():
                    if path_k.replace("\\", "/") == norm_file:
                        valid_lines = lines_v
                        break

            if not valid_lines:
                continue

            # Check if any line in [start_line, end_line] is in valid_lines
            line_range = set(range(f.start_line, f.end_line + 1))
            if line_range & valid_lines:
                filtered.append(f)

        return filtered
