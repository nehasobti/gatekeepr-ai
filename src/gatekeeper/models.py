"""Core data models for Gatekeeper AI."""

from __future__ import annotations

import hashlib
import re
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        order = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return order[self]

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        order = {
            Confidence.HIGH: 3,
            Confidence.MEDIUM: 2,
            Confidence.LOW: 1,
        }
        return order[self]

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Confidence):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Confidence):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Confidence):
            return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Confidence):
            return NotImplemented
        return self.rank < other.rank


class Category(StrEnum):
    INJECTION = "injection"
    AUTH = "auth"
    SECRETS = "secrets"
    SECRES = "secrets"  # backwards compatibility alias
    CRYPTO = "crypto"
    XSS = "xss"
    SSRF = "ssrf"
    DESERIALIZATION = "deserialization"
    ACCESS_CONTROL = "access_control"
    ERROR_HANDLING = "error_handling"
    PERFORMANCE = "performance"
    MAINTAINABILITY = "maintainability"
    BUG = "bug"
    OTHER = "other"


class Verdict(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


def generate_finding_id(
    file: str,
    category: str | Category,
    title: str,
    normalized_snippet: str = "",
) -> str:
    """Generate a stable fingerprint hash for a finding."""
    cat_str = category.value if isinstance(category, Category) else str(category)
    norm_text = (
        re.sub(r"\s+", " ", f"{file}:{cat_str}:{title}:{normalized_snippet}").strip().lower()
    )
    return hashlib.sha256(norm_text.encode("utf-8")).hexdigest()[:16]


class Finding(BaseModel):
    id: str = Field(description="Stable fingerprint ID")
    file: str = Field(description="Path relative to repo root")
    start_line: int = Field(description="Start line in new file")
    end_line: int = Field(description="End line in new file")
    severity: Severity = Field(description="Severity level")
    confidence: Confidence = Field(description="Confidence level")
    category: Category = Field(description="Issue category")
    owasp: str | None = Field(default=None, description="OWASP category reference")
    cwe: str | None = Field(default=None, description="CWE reference")
    title: str = Field(max_length=100, description="Short summary under 100 characters")
    explanation: str = Field(description="Explanation of the issue")
    suggested_fix: str = Field(description="Actionable suggested fix")
    source: list[str] = Field(
        default_factory=lambda: ["claude"],
        description="Source scanner or LLM",
    )

    @classmethod
    def compute_fingerprint(cls, rule: str, file: str, snippet: str = "") -> str:
        """Compute stable fingerprint for a scanner rule."""
        norm = re.sub(r"\s+", " ", f"{rule}:{file}:{snippet}").strip().lower()
        return hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16]

    @classmethod
    def create(
        cls,
        file: str,
        start_line: int,
        end_line: int,
        severity: Severity,
        category: Category,
        title: str,
        explanation: str,
        suggested_fix: str,
        confidence: Confidence = Confidence.HIGH,
        owasp: str | None = None,
        cwe: str | None = None,
        source: list[str] | None = None,
        normalized_snippet: str = "",
    ) -> Finding:
        title_clamped = title[:100]
        finding_id = generate_finding_id(file, category, title_clamped, normalized_snippet)
        return cls(
            id=finding_id,
            file=file,
            start_line=start_line,
            end_line=end_line,
            severity=severity,
            confidence=confidence,
            category=category,
            owasp=owasp,
            cwe=cwe,
            title=title_clamped,
            explanation=explanation,
            suggested_fix=suggested_fix,
            source=source or ["claude"],
        )


class AuditSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> AuditSummary:
        counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 0,
        }
        for f in findings:
            counts[f.severity] += 1
        return cls(
            critical=counts[Severity.CRITICAL],
            high=counts[Severity.HIGH],
            medium=counts[Severity.MEDIUM],
            low=counts[Severity.LOW],
            info=counts[Severity.INFO],
            total=len(findings),
        )


class AuditMetadata(BaseModel):
    tool_version: str = "1.0.0"
    prompt_version: str = "1.0.0"
    model: str = "claude-sonnet-latest"
    config_hash: str = ""
    pr_id: str | None = None
    commit_sha: str | None = None
    target_branch: str | None = None
    source_branch: str | None = None
    start_time: str = ""
    duration_seconds: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    estimated_cost_usd: float = 0.0
    skipped_files: list[str] = Field(default_factory=list)
    dropped_findings_count: int = 0
    extra: dict[str, Any] = Field(default_factory=dict)


class AuditResult(BaseModel):
    verdict: Verdict
    findings: list[Finding] = Field(default_factory=list)
    summary: AuditSummary = Field(default_factory=AuditSummary)
    metadata: AuditMetadata = Field(default_factory=AuditMetadata)
    error_message: str | None = None
