"""Unit tests for finding deduplication and merging."""

from gatekeeper.engine.merge import merge_and_dedupe_findings
from gatekeeper.models import Category, Confidence, Finding, Severity


def test_merge_same_location_and_category() -> None:
    f1 = Finding.create(
        file="src/app.py",
        start_line=15,
        end_line=15,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        category=Category.INJECTION,
        title="SQL injection",
        explanation="Untrusted input",
        suggested_fix="Bind parameters",
        source=["semgrep"],
    )
    f2 = Finding.create(
        file="src/app.py",
        start_line=15,
        end_line=15,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        category=Category.INJECTION,
        title="SQL injection detected",
        explanation="Dangerous string concatenation",
        suggested_fix="Use parameterized queries",
        source=["claude"],
    )

    merged = merge_and_dedupe_findings([[f1], [f2]])
    assert len(merged) == 1
    result = merged[0]
    # Retains highest severity and confidence
    assert result.severity == Severity.CRITICAL
    assert result.confidence == Confidence.HIGH
    # Merges sources
    assert set(result.source) == {"semgrep", "claude"}


def test_dedupe_different_categories() -> None:
    f1 = Finding.create(
        file="src/app.py",
        start_line=15,
        end_line=15,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.INJECTION,
        title="SQL injection",
        explanation="Untrusted input",
        suggested_fix="Bind parameters",
    )
    f2 = Finding.create(
        file="src/app.py",
        start_line=15,
        end_line=15,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SECRES,
        title="Secret leak",
        explanation="API key",
        suggested_fix="Env var",
    )

    merged = merge_and_dedupe_findings([[f1], [f2]])
    assert len(merged) == 2
