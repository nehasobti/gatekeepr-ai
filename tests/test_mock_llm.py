"""Unit tests for deterministic MockLLMClient scanning fixtures."""

from pathlib import Path

from gatekeeper.config import GatekeeperConfig
from gatekeeper.diff.chunker import chunk_diff
from gatekeeper.diff.parser import parse_diff
from gatekeeper.llm.mock import MockLLMClient
from gatekeeper.models import Category, Severity


def test_mock_llm_flags_vulnerabilities() -> None:
    vulnerable_file = Path(__file__).parent / "fixtures" / "vulnerable" / "app.py"
    code = vulnerable_file.read_text(encoding="utf-8")

    # Construct unified diff representation
    diff_text = f"""diff --git a/app.py b/app.py
new file mode 100644
--- /dev/null
+++ b/app.py
@@ -0,0 +1,{len(code.splitlines())} @@
""" + "\n".join(f"+{line}" for line in code.splitlines())

    diff_res = parse_diff(diff_text)
    chunks = chunk_diff(diff_res.files)

    mock_client = MockLLMClient(config=GatekeeperConfig())
    all_findings = []
    for chunk in chunks:
        findings = mock_client.review_chunk(chunk.content, "security", chunk.file_valid_lines)
        all_findings.extend(findings)

    assert len(all_findings) >= 4

    categories = {f.category for f in all_findings}
    assert Category.INJECTION in categories  # SQL Injection
    assert Category.SECRES in categories  # API key
    assert Category.XSS in categories  # XSS
    assert Category.DESERIALIZATION in categories  # Pickle deserialization

    # Check that critical findings are marked critical
    criticals = [f for f in all_findings if f.severity == Severity.CRITICAL]
    assert len(criticals) >= 2


def test_mock_llm_passes_clean_code() -> None:
    clean_file = Path(__file__).parent / "fixtures" / "clean" / "app.py"
    code = clean_file.read_text(encoding="utf-8")

    diff_text = f"""diff --git a/app.py b/app.py
new file mode 100644
--- /dev/null
+++ b/app.py
@@ -0,0 +1,{len(code.splitlines())} @@
""" + "\n".join(f"+{line}" for line in code.splitlines())

    diff_res = parse_diff(diff_text)
    chunks = chunk_diff(diff_res.files)

    mock_client = MockLLMClient(config=GatekeeperConfig())
    all_findings = []
    for chunk in chunks:
        findings = mock_client.review_chunk(chunk.content, "security", chunk.file_valid_lines)
        all_findings.extend(findings)

    assert len(all_findings) == 0
