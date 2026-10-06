"""Secret redaction and sensitive data masking module."""

from __future__ import annotations

import os
import re

# Standard high-confidence secret patterns (similar to gitleaks)
SECRET_PATTERNS: list[re.Pattern[str]] = [
    # AWS access keys
    re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    # GitHub personal access tokens
    re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{16,})\b"),
    # Anthropic API keys
    re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b"),
    # OpenAI API keys
    re.compile(r"\b(sk-[A-Za-z0-9]{20,})\b"),
    # Slack tokens
    re.compile(r"\b(xox[baprs]-[A-Za-z0-9_\-]{10,})\b"),
    # Private Key blocks
    re.compile(
        r"-----BEGIN[ A-Z0-9_-]+PRIVATE KEY-----.*?-----END[ A-Z0-9_-]+PRIVATE KEY-----", re.DOTALL
    ),
    # Generic bearer tokens
    re.compile(r"(?i)\bBearer\s+([A-Za-z0-9\-_.~+/]{16,}=*)"),
    # Generic assigned passwords/secrets
    re.compile(
        r"""(?i)(password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*['"]([^'"]{8,})['"]"""
    ),
]


def get_environment_secrets() -> set[str]:
    """Collect sensitive secret values from the current environment variables."""
    secrets: set[str] = set()
    sensitive_substrings = ("KEY", "TOKEN", "SECRET", "PASSWORD", "AUTH", "PASSWD", "CREDENTIAL")

    for env_var, value in os.environ.items():
        if any(substr in env_var.upper() for substr in sensitive_substrings):
            val = value.strip()
            # Only redact non-trivial secret values to avoid over-redacting empty or generic values
            if len(val) >= 6 and not val.startswith("GK_") and not val.startswith("GITHUB_API_"):
                secrets.add(val)

    return secrets


def redact_text(text: str, extra_secrets: set[str] | None = None) -> str:
    """Mask sensitive credentials and known environment secrets with '****'."""
    if not text:
        return text

    redacted = text

    # 1. Mask known environment secret values
    known_secrets = get_environment_secrets()
    if extra_secrets:
        known_secrets.update(extra_secrets)

    for secret_val in sorted(known_secrets, key=len, reverse=True):
        if secret_val in redacted:
            redacted = redacted.replace(secret_val, "****")

    # 2. Mask pattern-based secrets
    for pattern in SECRET_PATTERNS:

        def replace_match(m: re.Match[str]) -> str:
            # If the regex has groups, mask the matched secret group or full match
            matched_str = m.group(0)
            if m.lastindex and m.lastindex >= 1:
                secret_sub = m.group(m.lastindex)
                return matched_str.replace(secret_sub, "****")
            return "****"

        redacted = pattern.sub(replace_match, redacted)

    return redacted
