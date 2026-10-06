"""Tests for LLM triage engine."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from gatekeeper.config import GatekeeperConfig
from gatekeeper.engine.triage import extract_finding_context, triage_scanner_findings
from gatekeeper.llm.client import LLMClient
from gatekeeper.llm.mock import MockLLMClient
from gatekeeper.models import Category, Confidence, Finding, Severity


def test_extract_finding_context(tmp_path: Path) -> None:
    code_file = tmp_path / "app.py"
    code_lines = [f"line_{i} = {i}" for i in range(1, 21)]
    code_file.write_text("\n".join(code_lines), encoding="utf-8")

    f = Finding.create(
        file="app.py",
        start_line=10,
        end_line=10,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.INJECTION,
        title="Test finding",
        explanation="Explanation",
        suggested_fix="Fix",
    )

    context = extract_finding_context(f, tmp_path, radius=2)
    assert ">   10 | line_10 = 10" in context
    assert "     8 | line_8 = 8" in context
    assert "    12 | line_12 = 12" in context


def test_triage_scanner_findings_with_mock(tmp_path: Path) -> None:
    code_file = tmp_path / "service.py"
    code_file.write_text("def run():\n    pass\n", encoding="utf-8")

    f_valid = Finding.create(
        file="service.py",
        start_line=1,
        end_line=1,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.INJECTION,
        title="Valid finding",
        explanation="Confirmed risk",
        suggested_fix="Fix",
    )
    f_fp = Finding.create(
        file="service.py",
        start_line=2,
        end_line=2,
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        category=Category.BUG,
        title="False-positive finding",
        explanation="This is a false-positive detection",
        suggested_fix="Ignore",
    )

    mock_llm = MockLLMClient(config=GatekeeperConfig())
    confirmed, dismissed = triage_scanner_findings([f_valid, f_fp], tmp_path, mock_llm)

    assert len(confirmed) == 1
    assert confirmed[0].id == f_valid.id
    assert len(dismissed) == 1
    assert dismissed[0].id == f_fp.id


def test_triage_scanner_findings_llm_client_mocked(tmp_path: Path) -> None:
    code_file = tmp_path / "service.py"
    code_file.write_text("code = 1\n", encoding="utf-8")

    f1 = Finding.create(
        file="service.py",
        start_line=1,
        end_line=1,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        category=Category.SECRETS,
        title="Secret finding",
        explanation="API key",
        suggested_fix="Env var",
    )

    llm = LLMClient(config=GatekeeperConfig(), api_key="sk-ant-test1234567890123456")

    # Mock Claude message response
    mock_msg = MagicMock()
    mock_block = MagicMock()
    mock_block.type = "tool_use"
    mock_block.name = "submit_triage"
    mock_block.input = {
        "verdicts": [{"finding_id": f1.id, "is_valid": True, "reason": "True positive key"}]
    }
    mock_msg.content = [mock_block]
    mock_msg.usage.input_tokens = 50
    mock_msg.usage.output_tokens = 25
    mock_msg.usage.cache_read_input_tokens = 0
    mock_msg.usage.cache_creation_input_tokens = 0

    llm.client.messages.create = MagicMock(return_value=mock_msg)  # type: ignore[method-assign]

    confirmed, dismissed = triage_scanner_findings([f1], tmp_path, llm)
    assert len(confirmed) == 1
    assert confirmed[0].id == f1.id
    assert len(dismissed) == 0
