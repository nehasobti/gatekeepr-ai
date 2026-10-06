"""Unit and integration tests for Typer CLI commands."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from gatekeeper.cli import app
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

runner = CliRunner()


def test_cli_version() -> None:
    res = runner.invoke(app, ["version"])
    assert res.exit_code == 0
    assert "Gatekeeper AI version" in res.stdout
    assert "Prompt template version" in res.stdout


def test_cli_init_creates_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    res = runner.invoke(app, ["init", "--preset", "strict"])
    assert res.exit_code == 0
    assert (tmp_path / "gatekeeper.yml").exists()
    content = (tmp_path / "gatekeeper.yml").read_text(encoding="utf-8")
    assert "critical: 1" in content


def test_cli_validate_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    config_file = tmp_path / "gatekeeper.yml"
    config_file.write_text("version: 1\n", encoding="utf-8")

    res = runner.invoke(app, ["validate-config", "--config", str(config_file)])
    assert res.exit_code == 0
    assert "is valid" in res.stdout


def test_cli_validate_config_fails_on_missing_file() -> None:
    res = runner.invoke(app, ["validate-config", "--config", "non_existent_file.yml"])
    assert res.exit_code == 2


def test_cli_report_rebuild(tmp_path: Path) -> None:
    f = Finding.create(
        file="src/test.py",
        start_line=1,
        end_line=1,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.INJECTION,
        title="Test finding",
        explanation="Test explanation",
        suggested_fix="Fix",
    )
    result = AuditResult(
        verdict=Verdict.FAIL,
        findings=[f],
        summary=AuditSummary.from_findings([f]),
        metadata=AuditMetadata(),
    )
    report_json = tmp_path / "report.json"
    report_json.write_text(result.model_dump_json(), encoding="utf-8")

    out_html = tmp_path / "rebuilt.html"
    res = runner.invoke(
        app, ["report", "--from", str(report_json), "--format", "html", "--out", str(out_html)]
    )
    assert res.exit_code == 0
    assert out_html.exists()

    out_md = tmp_path / "rebuilt.md"
    res = runner.invoke(
        app, ["report", "--from", str(report_json), "--format", "markdown", "--out", str(out_md)]
    )
    assert res.exit_code == 0
    assert out_md.exists()

    out_sarif = tmp_path / "rebuilt.sarif"
    res = runner.invoke(
        app, ["report", "--from", str(report_json), "--format", "sarif", "--out", str(out_sarif)]
    )
    assert res.exit_code == 0
    assert out_sarif.exists()


def test_cli_baseline_create(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    config_file = tmp_path / "gatekeeper.yml"
    config_file.write_text("version: 1\n", encoding="utf-8")
    baseline_out = tmp_path / "baseline.json"

    res = runner.invoke(
        app,
        [
            "baseline",
            "create",
            "--config",
            str(config_file),
            "--output",
            str(baseline_out),
            "--mock",
        ],
    )
    assert res.exit_code == 0
    assert baseline_out.exists()
    data = json.loads(baseline_out.read_text(encoding="utf-8"))
    assert "findings" in data
