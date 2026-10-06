"""Unit tests for configuration loading and validation."""

from pathlib import Path

import pytest

from gatekeeper.config import (
    LENIENT_PRESET_YAML,
    STRICT_PRESET_YAML,
    GatekeeperConfig,
    load_config,
)
from gatekeeper.models import Confidence


def test_default_config_instantiation() -> None:
    config = GatekeeperConfig()
    assert config.version == 1
    assert config.model.name == "claude-sonnet-latest"
    assert "security" in config.review.passes
    assert "quality" in config.review.passes
    assert config.gate.fail_on.critical == 1
    assert config.gate.fail_on.high == 1
    assert config.gate.min_confidence == Confidence.MEDIUM


def test_load_config_from_missing_file_falls_back_or_raises(tmp_path: Path) -> None:
    non_existent = tmp_path / "does_not_exist.yml"
    with pytest.raises(FileNotFoundError):
        load_config(non_existent)


def test_load_config_custom_file(tmp_path: Path) -> None:
    custom_file = tmp_path / "custom.yml"
    custom_file.write_text(
        """
version: 1
gate:
  fail_on:
    critical: 5
    high: 10
    medium: 20
review:
  custom_rules:
    - "No plaintext passwords"
""",
        encoding="utf-8",
    )
    cfg = load_config(custom_file)
    assert cfg.gate.fail_on.critical == 5
    assert cfg.gate.fail_on.high == 10
    assert cfg.gate.fail_on.medium == 20
    assert "No plaintext passwords" in cfg.review.custom_rules


def test_presets_parsing(tmp_path: Path) -> None:
    strict_file = tmp_path / "strict.yml"
    strict_file.write_text(STRICT_PRESET_YAML, encoding="utf-8")
    strict_cfg = load_config(strict_file)
    assert strict_cfg.gate.fail_on.medium == 5

    lenient_file = tmp_path / "lenient.yml"
    lenient_file.write_text(LENIENT_PRESET_YAML, encoding="utf-8")
    lenient_cfg = load_config(lenient_file)
    assert lenient_cfg.gate.fail_on.high == 999
    assert lenient_cfg.gate.fail_on.medium == 999


def test_config_hash_consistency() -> None:
    cfg1 = GatekeeperConfig()
    cfg2 = GatekeeperConfig()
    assert cfg1.compute_hash() == cfg2.compute_hash()
    assert len(cfg1.compute_hash()) == 16
