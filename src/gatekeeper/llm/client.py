"""Anthropic Claude LLM client with prompt caching, forced tool schemas, and retries."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import anthropic
import jinja2
from anthropic.types import Message
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from gatekeeper.config import GatekeeperConfig
from gatekeeper.models import (
    Category,
    Confidence,
    Finding,
    Severity,
    generate_finding_id,
)

PROMPT_VERSION = "1.0.0"

SUBMIT_FINDINGS_TOOL: dict[str, Any] = {
    "name": "submit_findings",
    "description": "Submit code review findings discovered in the diff.",
    "input_schema": {
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "file": {
                            "type": "string",
                            "description": "Path relative to repo root",
                        },
                        "start_line": {
                            "type": "integer",
                            "description": "Start line number in new file",
                        },
                        "end_line": {
                            "type": "integer",
                            "description": "End line number in new file",
                        },
                        "severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "info"],
                        },
                        "confidence": {
                            "type": "string",
                            "enum": ["high", "medium", "low"],
                        },
                        "category": {
                            "type": "string",
                            "enum": [
                                "injection",
                                "auth",
                                "secrets",
                                "crypto",
                                "xss",
                                "ssrf",
                                "deserialization",
                                "access_control",
                                "error_handling",
                                "performance",
                                "maintainability",
                                "bug",
                                "other",
                            ],
                        },
                        "owasp": {
                            "type": ["string", "null"],
                            "description": "OWASP category e.g. A03:2021 Injection",
                        },
                        "cwe": {
                            "type": ["string", "null"],
                            "description": "CWE id e.g. CWE-89",
                        },
                        "title": {
                            "type": "string",
                            "maxLength": 100,
                            "description": "Short issue title under 100 characters",
                        },
                        "explanation": {
                            "type": "string",
                            "description": "Clear explanation of why this is an issue",
                        },
                        "suggested_fix": {
                            "type": "string",
                            "description": "Actionable suggested fix",
                        },
                    },
                    "required": [
                        "file",
                        "start_line",
                        "end_line",
                        "severity",
                        "confidence",
                        "category",
                        "title",
                        "explanation",
                        "suggested_fix",
                    ],
                },
            }
        },
        "required": ["findings"],
    },
}


@dataclass
class TokenUsageTracker:
    input_tokens: int = 0
    output_tokens: int = 0
    cached_read_tokens: int = 0
    cached_creation_tokens: int = 0

    def add(
        self,
        input_tokens: int,
        output_tokens: int,
        cached_read: int = 0,
        cached_creation: int = 0,
    ) -> None:
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens
        self.cached_read_tokens += cached_read
        self.cached_creation_tokens += cached_creation

    @property
    def total_cached(self) -> int:
        return self.cached_read_tokens + self.cached_creation_tokens

    def calculate_cost_usd(self) -> float:
        # Standard Claude 3.5 / 3.7 Sonnet pricing
        base_input_rate = 3.00 / 1_000_000
        cache_read_rate = 0.30 / 1_000_000
        cache_write_rate = 3.75 / 1_000_000
        output_rate = 15.00 / 1_000_000

        uncached_input = max(0, self.input_tokens - self.cached_read_tokens)
        cost = (
            (uncached_input * base_input_rate)
            + (self.cached_read_tokens * cache_read_rate)
            + (self.cached_creation_tokens * cache_write_rate)
            + (self.output_tokens * output_rate)
        )
        return round(cost, 4)


class LLMClient:
    """Claude LLM client handling prompt rendering, tool calls, and caching."""

    def __init__(self, config: GatekeeperConfig, api_key: str | None = None) -> None:
        self.config = config
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable is not set")

        self.client = anthropic.Anthropic(api_key=self.api_key)
        self.tracker = TokenUsageTracker()
        self.prompts_dir = Path(__file__).parent / "prompts"
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(self.prompts_dir)),
            autoescape=False,
        )

    def render_system_prompt(self, pass_name: str) -> str:
        template_file = f"{pass_name}.md"
        template = self.jinja_env.get_template(template_file)
        return str(
            template.render(
                prompt_version=PROMPT_VERSION,
                custom_rules=self.config.review.custom_rules,
            )
        )

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(
            (
                anthropic.RateLimitError,
                anthropic.InternalServerError,
                anthropic.APIConnectionError,
            )
        ),
    )
    def _call_claude_with_tool(
        self,
        system_prompt: str,
        user_message: str,
    ) -> Message:
        system_blocks: list[Any] = [
            {
                "type": "text",
                "text": system_prompt,
                "cache_control": {"type": "ephemeral"},
            }
        ]
        messages_payload: list[Any] = [{"role": "user", "content": user_message}]
        tools_payload: list[Any] = [SUBMIT_FINDINGS_TOOL]
        tool_choice_payload: dict[str, Any] = {"type": "tool", "name": "submit_findings"}

        response = self.client.messages.create(  # type: ignore[call-overload]
            model=self.config.model.name,
            max_tokens=self.config.model.max_output_tokens,
            system=system_blocks,
            messages=messages_payload,
            tools=tools_payload,
            tool_choice=tool_choice_payload,
        )
        if isinstance(response, Message):
            return response
        raise RuntimeError(f"Unexpected response type from Claude: {type(response)}")

    def review_chunk(
        self,
        chunk_content: str,
        pass_name: str,
        valid_lines: dict[str, set[int]],
    ) -> list[Finding]:
        """Run a review pass over a diff chunk and extract findings."""
        if self.tracker.input_tokens >= self.config.budget.max_input_tokens_per_run:
            if self.config.budget.on_budget_exceeded == "fail":
                raise RuntimeError("Token budget exceeded limit")
            elif self.config.budget.on_budget_exceeded == "skip_remaining":
                return []

        system_prompt = self.render_system_prompt(pass_name)
        user_message = f"Please review the following git diff for {pass_name}:\n\n```diff\n{chunk_content}\n```"

        response = self._call_claude_with_tool(system_prompt, user_message)

        # Record usage
        cache_read = getattr(response.usage, "cache_read_input_tokens", 0) or 0
        cache_write = getattr(response.usage, "cache_creation_input_tokens", 0) or 0
        self.tracker.add(
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            cached_read=cache_read,
            cached_creation=cache_write,
        )

        findings: list[Finding] = []
        for block in response.content:
            if (
                block.type == "tool_use"
                and block.name == "submit_findings"
                and isinstance(block.input, dict)
            ):
                findings_data = block.input.get("findings", [])
                if isinstance(findings_data, list):
                    for item in findings_data:
                        if isinstance(item, dict):
                            parsed = self._parse_finding_item(item, valid_lines)
                            if parsed is not None:
                                findings.append(parsed)

        return findings

    def _parse_finding_item(
        self,
        item: dict[str, Any],
        valid_lines: dict[str, set[int]],
    ) -> Finding | None:
        try:
            file_path = str(item.get("file", ""))
            start_line = int(item.get("start_line", 0))
            end_line = int(item.get("end_line", start_line))

            file_valid = valid_lines.get(file_path)
            if file_valid is not None:
                lines_in_range = set(range(start_line, end_line + 1))
                if not (lines_in_range & file_valid):
                    return None

            sev = Severity(str(item.get("severity", "medium")).lower())
            conf = Confidence(str(item.get("confidence", "medium")).lower())
            cat_str = str(item.get("category", "other")).lower()
            try:
                cat = Category(cat_str)
            except ValueError:
                cat = Category.OTHER

            title = str(item.get("title", ""))[:100]
            expl = str(item.get("explanation", ""))
            fix = str(item.get("suggested_fix", ""))
            owasp = item.get("owasp")
            cwe = item.get("cwe")

            f_id = generate_finding_id(file_path, cat, title)

            return Finding(
                id=f_id,
                file=file_path,
                start_line=start_line,
                end_line=end_line,
                severity=sev,
                confidence=conf,
                category=cat,
                owasp=str(owasp) if owasp else None,
                cwe=str(cwe) if cwe else None,
                title=title,
                explanation=expl,
                suggested_fix=fix,
                source=["claude"],
            )
        except Exception:
            return None
