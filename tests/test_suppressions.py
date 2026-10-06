"""Unit tests for inline suppression markers and baseline filtering."""

import json
from pathlib import Path

from gatekeeper.config import SuppressionsConfig
from gatekeeper.engine.suppressions import apply_suppressions, check_inline_suppression
from gatekeeper.models import Category, Confidence, Finding, Severity


def test_inline_suppression_requires_reason(tmp_path: Path) -> None:
    test_file = tmp_path / "app.py"
    test_file.write_text(
        """line 1
# gatekeeper-ignore: false positive sanitized in middleware
vulnerable_call()
line 4
""",
        encoding="utf-8",
    )

    # Line 3 has suppression on line 2
    suppressed, reason = check_inline_suppression(
        "app.py", 3, marker="gatekeeper-ignore", repo_root=tmp_path
    )
    assert suppressed is True
    assert "false positive sanitized in middleware" in reason


def test_inline_suppression_without_reason_is_ignored(tmp_path: Path) -> None:
    test_file = tmp_path / "app.py"
    test_file.write_text(
        """line 1
# gatekeeper-ignore:
vulnerable_call()
""",
        encoding="utf-8",
    )

    suppressed, _ = check_inline_suppression(
        "app.py", 3, marker="gatekeeper-ignore", repo_root=tmp_path
    )
    assert suppressed is False


def test_baseline_suppression(tmp_path: Path) -> None:
    f1 = Finding.create(
        file="src/app.py",
        start_line=10,
        end_line=10,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.INJECTION,
        title="SQL Injection",
        explanation="Untrusted",
        suggested_fix="Fix",
    )
    f2 = Finding.create(
        file="src/app.py",
        start_line=20,
        end_line=20,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.SECRES,
        title="Secret",
        explanation="Token",
        suggested_fix="Fix",
    )

    baseline_file = tmp_path / "baseline.json"
    baseline_file.write_text(json.dumps({"findings": [{"id": f1.id}]}), encoding="utf-8")

    cfg = SuppressionsConfig(baseline_file=str(baseline_file))
    active, dropped = apply_suppressions([f1, f2], cfg, repo_root=tmp_path)

    assert len(active) == 1
    assert active[0].id == f2.id
    assert len(dropped) == 1
    assert dropped[0][0].id == f1.id
    assert "suppressed by baseline" in dropped[0][1]
