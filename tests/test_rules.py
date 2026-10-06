"""Unit tests for gate rules and confidence thresholds."""

from gatekeeper.config import FailOnConfig, GateConfig
from gatekeeper.engine.rules import evaluate_gate, filter_by_confidence
from gatekeeper.models import Category, Confidence, Finding, Severity, Verdict


def make_finding(
    sev: Severity,
    conf: Confidence = Confidence.HIGH,
    cat: Category = Category.INJECTION,
) -> Finding:
    return Finding.create(
        file="src/test.py",
        start_line=10,
        end_line=10,
        severity=sev,
        confidence=conf,
        category=cat,
        title="Test issue",
        explanation="Testing",
        suggested_fix="Fix it",
    )


def test_confidence_filtering() -> None:
    findings = [
        make_finding(Severity.HIGH, Confidence.HIGH),
        make_finding(Severity.HIGH, Confidence.MEDIUM),
        make_finding(Severity.HIGH, Confidence.LOW),
    ]
    filtered = filter_by_confidence(findings, Confidence.MEDIUM)
    assert len(filtered) == 2
    assert all(f.confidence >= Confidence.MEDIUM for f in filtered)


def test_evaluate_gate_pass() -> None:
    findings = [make_finding(Severity.LOW)]
    cfg = GateConfig(
        fail_on=FailOnConfig(critical=1, high=1, medium=10, low=5),
        min_confidence=Confidence.MEDIUM,
    )
    verdict, reasons = evaluate_gate(findings, cfg)
    assert verdict == Verdict.PASS
    assert len(reasons) == 0


def test_evaluate_gate_fail_on_critical() -> None:
    findings = [make_finding(Severity.CRITICAL)]
    cfg = GateConfig(
        fail_on=FailOnConfig(critical=1, high=1, medium=10),
        min_confidence=Confidence.MEDIUM,
    )
    verdict, reasons = evaluate_gate(findings, cfg)
    assert verdict == Verdict.FAIL
    assert any("Critical findings" in r for r in reasons)


def test_evaluate_gate_ignores_low_confidence() -> None:
    findings = [make_finding(Severity.CRITICAL, conf=Confidence.LOW)]
    cfg = GateConfig(
        fail_on=FailOnConfig(critical=1, high=1, medium=10),
        min_confidence=Confidence.MEDIUM,
    )
    verdict, _ = evaluate_gate(findings, cfg)
    assert verdict == Verdict.PASS
