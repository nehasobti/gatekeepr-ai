"""Unit tests for Claude LLMClient with mocked Message objects."""

from unittest.mock import MagicMock

import pytest
from anthropic.types import Message, ToolUseBlock, Usage

from gatekeeper.config import GatekeeperConfig
from gatekeeper.llm.client import PROMPT_VERSION, LLMClient, TokenUsageTracker
from gatekeeper.models import Category, Severity


def test_token_usage_tracker_and_cost() -> None:
    tracker = TokenUsageTracker()
    tracker.add(input_tokens=10000, output_tokens=2000, cached_read=4000, cached_creation=1000)

    assert tracker.input_tokens == 10000
    assert tracker.output_tokens == 2000
    assert tracker.cached_read_tokens == 4000
    assert tracker.cached_creation_tokens == 1000
    assert tracker.total_cached == 5000

    cost = tracker.calculate_cost_usd()
    assert cost > 0.0


def test_render_system_prompt() -> None:
    cfg = GatekeeperConfig()
    cfg.review.custom_rules = ["Custom rule A", "Custom rule B"]
    client = LLMClient(config=cfg, api_key="sk-ant-test-key")

    prompt = client.render_system_prompt("security")
    assert PROMPT_VERSION in prompt
    assert "Custom rule A" in prompt
    assert "OWASP Top 10" in prompt


def test_review_chunk_success() -> None:
    cfg = GatekeeperConfig()
    client = LLMClient(config=cfg, api_key="sk-ant-test-key")

    mock_msg = Message(
        id="msg_123",
        type="message",
        role="assistant",
        model="claude-sonnet-latest",
        content=[
            ToolUseBlock(
                id="toolu_123",
                type="tool_use",
                name="submit_findings",
                input={
                    "findings": [
                        {
                            "file": "src/app.py",
                            "start_line": 5,
                            "end_line": 5,
                            "severity": "critical",
                            "confidence": "high",
                            "category": "injection",
                            "owasp": "A03:2021 Injection",
                            "cwe": "CWE-89",
                            "title": "SQL Injection",
                            "explanation": "Untrusted input",
                            "suggested_fix": "Use parameterized queries",
                        }
                    ]
                },
            )
        ],
        usage=Usage(
            input_tokens=120,
            output_tokens=60,
            cache_read_input_tokens=40,
            cache_creation_input_tokens=0,
        ),
    )

    client._call_claude_with_tool = MagicMock(return_value=mock_msg)  # type: ignore[method-assign]

    findings = client.review_chunk(
        chunk_content="### File: src/app.py\n    5 + query = 'SELECT'",
        pass_name="security",
        valid_lines={"src/app.py": {5}},
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.file == "src/app.py"
    assert f.start_line == 5
    assert f.severity == Severity.CRITICAL
    assert f.category == Category.INJECTION
    assert client.tracker.input_tokens == 120
    assert client.tracker.cached_read_tokens == 40


def test_review_chunk_drops_findings_outside_diff() -> None:
    cfg = GatekeeperConfig()
    client = LLMClient(config=cfg, api_key="sk-ant-test-key")

    mock_msg = Message(
        id="msg_123",
        type="message",
        role="assistant",
        model="claude-sonnet-latest",
        content=[
            ToolUseBlock(
                id="toolu_123",
                type="tool_use",
                name="submit_findings",
                input={
                    "findings": [
                        {
                            "file": "src/app.py",
                            "start_line": 99,
                            "end_line": 99,
                            "severity": "high",
                            "confidence": "high",
                            "category": "injection",
                            "title": "Outside diff",
                            "explanation": "Not in diff",
                            "suggested_fix": "Fix",
                        }
                    ]
                },
            )
        ],
        usage=Usage(input_tokens=100, output_tokens=50),
    )

    client._call_claude_with_tool = MagicMock(return_value=mock_msg)  # type: ignore[method-assign]

    # Line 99 is not in valid_lines
    findings = client.review_chunk(
        chunk_content="diff",
        pass_name="security",
        valid_lines={"src/app.py": {5, 6}},
    )
    assert len(findings) == 0


def test_budget_exceeded_handling() -> None:
    cfg = GatekeeperConfig()
    cfg.budget.max_input_tokens_per_run = 100
    cfg.budget.on_budget_exceeded = "fail"
    client = LLMClient(config=cfg, api_key="sk-ant-test-key")
    client.tracker.input_tokens = 200

    with pytest.raises(RuntimeError, match="Token budget exceeded"):
        client.review_chunk("diff", "security", {})

    cfg.budget.on_budget_exceeded = "skip_remaining"
    assert client.review_chunk("diff", "security", {}) == []
