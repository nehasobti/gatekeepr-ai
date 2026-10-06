"""Unit tests for secret redaction and credential masking."""

import pytest

from gatekeeper.security.redactor import get_environment_secrets, redact_text


def test_redact_known_patterns() -> None:
    text = """
    aws_key = "AKIA1234567890ABCDEF"
    github_pat = "ghp_1234567890abcdef1234567890abcdef"
    claude_key = "sk-ant-api03-abcdef12345678901234567890"
    openai_key = "sk-abcdef12345678901234"
    password = "SuperSecretPassword123"
    """

    redacted = redact_text(text)
    assert "AKIA1234567890ABCDEF" not in redacted
    assert "ghp_1234567890abcdef1234567890abcdef" not in redacted
    assert "sk-ant-" not in redacted
    assert "SuperSecretPassword123" not in redacted
    assert "****" in redacted


def test_redact_environment_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_APP_SECRET_TOKEN", "ultra-confidential-token-value")
    text = "Authorization: Bearer ultra-confidential-token-value in request"

    redacted = redact_text(text)
    assert "ultra-confidential-token-value" not in redacted
    assert "****" in redacted


def test_get_environment_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_PASSWORD", "db-pass-secret-999")
    monkeypatch.setenv("NORMAL_VAR", "hello-world")

    secrets = get_environment_secrets()
    assert "db-pass-secret-999" in secrets
    assert "hello-world" not in secrets
