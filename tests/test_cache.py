"""Unit tests for ChunkResultCache."""

from pathlib import Path

from gatekeeper.llm.cache import ChunkResultCache
from gatekeeper.models import Category, Confidence, Finding, Severity


def test_chunk_result_cache_hit_and_miss(tmp_path: Path) -> None:
    cache = ChunkResultCache(cache_dir=tmp_path / "cache")

    chunk_content = "diff line 1 + line 2"
    pass_name = "security"
    prompt_version = "1.0.0"
    model_name = "claude-sonnet-latest"
    custom_rules = ["No plaintext passwords"]

    # Miss initially
    assert cache.get(chunk_content, pass_name, prompt_version, model_name, custom_rules) is None

    # Save finding
    finding = Finding.create(
        file="src/app.py",
        start_line=1,
        end_line=1,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SECRES,
        title="Secret leak",
        explanation="Secret found",
        suggested_fix="Fix",
    )
    cache.put(chunk_content, pass_name, prompt_version, model_name, [finding], custom_rules)

    # Hit
    cached = cache.get(chunk_content, pass_name, prompt_version, model_name, custom_rules)
    assert cached is not None
    assert len(cached) == 1
    assert cached[0].id == finding.id
    assert cached[0].title == "Secret leak"

    # Miss if rules change
    assert (
        cache.get(chunk_content, pass_name, prompt_version, model_name, ["Different rule"]) is None
    )

    # Clear
    cache.clear()
    assert cache.get(chunk_content, pass_name, prompt_version, model_name, custom_rules) is None
