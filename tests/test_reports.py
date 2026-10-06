"""Unit tests for report generation (JSON, Markdown, HTML, SARIF)."""

import json
from pathlib import Path

from gatekeeper.models import (
    AuditMetadata,
    AuditResult,
    AuditSummary,
    Category,
    Confidence,
    Finding,
    Severity,
    Verdict,
)
from gatekeeper.report import (
    generate_html_report,
    generate_json_report,
    generate_markdown_content,
    generate_markdown_report,
    generate_sarif_report,
)


def create_sample_result() -> AuditResult:
    f = Finding.create(
        file="src/app.py",
        start_line=12,
        end_line=12,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        category=Category.INJECTION,
        owasp="A03:2021 Injection",
        cwe="CWE-89",
        title="SQL Injection vulnerability",
        explanation="Direct user input in SQL statement.",
        suggested_fix="Use parameterized queries.",
        source=["claude"],
    )
    return AuditResult(
        verdict=Verdict.FAIL,
        findings=[f],
        summary=AuditSummary.from_findings([f]),
        metadata=AuditMetadata(
            tool_version="0.1.0",
            prompt_version="1.0.0",
            model="claude-sonnet-latest",
            duration_seconds=1.23,
            input_tokens=1000,
            output_tokens=200,
            cached_tokens=400,
            estimated_cost_usd=0.0055,
        ),
    )


def test_markdown_report(tmp_path: Path) -> None:
    res = create_sample_result()
    content = generate_markdown_content(res)
    assert "## Gatekeeper AI Quality Gate: 🔴 **FAIL**" in content
    assert "SQL Injection vulnerability" in content
    assert "A03:2021" not in content or "src/app.py:12" in content

    out_file = tmp_path / "report.md"
    generate_markdown_report(res, out_file)
    assert out_file.exists()


def test_json_report(tmp_path: Path) -> None:
    res = create_sample_result()
    out_file = tmp_path / "report.json"
    generate_json_report(res, out_file)
    assert out_file.exists()

    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["verdict"] == "FAIL"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["severity"] == "critical"


def test_html_report(tmp_path: Path) -> None:
    res = create_sample_result()
    out_file = tmp_path / "report.html"
    generate_html_report(res, out_file)
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "SQL Injection vulnerability" in content
    assert "filterFindings" in content


def test_sarif_report(tmp_path: Path) -> None:
    res = create_sample_result()
    out_file = tmp_path / "report.sarif"
    generate_sarif_report(res, out_file)
    assert out_file.exists()

    sarif = json.loads(out_file.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Gatekeeper AI"
    assert len(run["results"]) == 1
    assert run["results"][0]["level"] == "error"
    assert (
        run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "src/app.py"
    )
