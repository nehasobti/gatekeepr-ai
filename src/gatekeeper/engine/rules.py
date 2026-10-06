"""Gate rule evaluator determining PASS/FAIL verdicts."""

from __future__ import annotations

from gatekeeper.config import GateConfig
from gatekeeper.models import (
    AuditSummary,
    Confidence,
    Finding,
    Verdict,
)


def filter_by_confidence(findings: list[Finding], min_confidence: Confidence) -> list[Finding]:
    """Filter out findings that do not meet the minimum confidence threshold."""
    return [f for f in findings if f.confidence >= min_confidence]


def evaluate_gate(findings: list[Finding], gate_config: GateConfig) -> tuple[Verdict, list[str]]:
    """Evaluate findings against gate fail_on thresholds and return verdict with violation reasons."""
    effective_findings = filter_by_confidence(findings, gate_config.min_confidence)
    summary = AuditSummary.from_findings(effective_findings)
    fail_reasons: list[str] = []

    if summary.critical >= gate_config.fail_on.critical:
        fail_reasons.append(
            f"Critical findings ({summary.critical}) reached threshold ({gate_config.fail_on.critical})"
        )

    if summary.high >= gate_config.fail_on.high:
        fail_reasons.append(
            f"High findings ({summary.high}) reached threshold ({gate_config.fail_on.high})"
        )

    if summary.medium >= gate_config.fail_on.medium:
        fail_reasons.append(
            f"Medium findings ({summary.medium}) reached threshold ({gate_config.fail_on.medium})"
        )

    if summary.low >= gate_config.fail_on.low:
        fail_reasons.append(
            f"Low findings ({summary.low}) reached threshold ({gate_config.fail_on.low})"
        )

    if fail_reasons:
        return Verdict.FAIL, fail_reasons

    return Verdict.PASS, []
