"""Result caching for chunk reviews to avoid redundant LLM calls on unchanged code."""

from __future__ import annotations

import contextlib
import hashlib
import json
from pathlib import Path
from typing import Any

from gatekeeper.models import Finding


class ChunkResultCache:
    """File-based cache for LLM chunk reviews."""

    def __init__(self, cache_dir: str | Path = ".gatekeeper/cache") -> None:
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _compute_key(
        self,
        chunk_content: str,
        pass_name: str,
        prompt_version: str,
        model_name: str,
        custom_rules: list[str] | None = None,
    ) -> str:
        data = {
            "chunk_content": chunk_content,
            "pass_name": pass_name,
            "prompt_version": prompt_version,
            "model_name": model_name,
            "custom_rules": sorted(custom_rules or []),
        }
        raw_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()

    def get(
        self,
        chunk_content: str,
        pass_name: str,
        prompt_version: str,
        model_name: str,
        custom_rules: list[str] | None = None,
    ) -> list[Finding] | None:
        """Retrieve cached findings if available."""
        key = self._compute_key(chunk_content, pass_name, prompt_version, model_name, custom_rules)
        cache_file = self.cache_dir / f"{key}.json"

        if not cache_file.exists():
            return None

        try:
            content = cache_file.read_text(encoding="utf-8")
            data = json.loads(content)
            findings_raw = data.get("findings", [])
            return [Finding.model_validate(f) for f in findings_raw]
        except Exception:
            return None

    def put(
        self,
        chunk_content: str,
        pass_name: str,
        prompt_version: str,
        model_name: str,
        findings: list[Finding],
        custom_rules: list[str] | None = None,
    ) -> None:
        """Store findings in the cache."""
        key = self._compute_key(chunk_content, pass_name, prompt_version, model_name, custom_rules)
        cache_file = self.cache_dir / f"{key}.json"

        data: dict[str, Any] = {
            "key": key,
            "pass_name": pass_name,
            "prompt_version": prompt_version,
            "model_name": model_name,
            "findings": [f.model_dump() for f in findings],
        }
        with contextlib.suppress(Exception):
            cache_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def clear(self) -> None:
        """Clear all cached entries."""
        for f in self.cache_dir.glob("*.json"):
            with contextlib.suppress(Exception):
                f.unlink()
