"""Deterministic mock LLM client for tests and offline audits."""

from __future__ import annotations

import re

from gatekeeper.config import GatekeeperConfig
from gatekeeper.llm.client import TokenUsageTracker
from gatekeeper.models import (
    Category,
    Confidence,
    Finding,
    Severity,
    generate_finding_id,
)


class MockLLMClient:
    """Deterministic mock LLM client that identifies planted issues in fixtures."""

    def __init__(self, config: GatekeeperConfig, _api_key: str | None = None) -> None:
        self.config = config
        self.tracker = TokenUsageTracker()

    def review_chunk(
        self,
        chunk_content: str,
        pass_name: str,
        valid_lines: dict[str, set[int]],
    ) -> list[Finding]:
        # Track simulated tokens
        sim_input = max(50, len(chunk_content) // 4)
        sim_output = 120
        self.tracker.add(
            input_tokens=sim_input,
            output_tokens=sim_output,
            cached_read=int(sim_input * 0.4),
            cached_creation=0,
        )

        findings: list[Finding] = []

        if pass_name == "security":
            findings.extend(self._scan_security_patterns(chunk_content, valid_lines))
        elif pass_name == "quality":
            findings.extend(self._scan_quality_patterns(chunk_content, valid_lines))

        return findings

    def _scan_security_patterns(
        self,
        chunk_content: str,
        valid_lines: dict[str, set[int]],
    ) -> list[Finding]:
        findings: list[Finding] = []
        lines = chunk_content.splitlines()

        curr_file = ""
        for line in lines:
            if line.startswith("### File: "):
                # Extract file name e.g. "### File: src/app.py" or with hunks
                header = line.replace("### File: ", "").split()[0]
                curr_file = header
                continue

            # Check if line has a line number: e.g. "   12 + ..."
            m = re.match(r"^\s*(\d+)\s*\+\s*(.*)$", line)
            if not m or not curr_file:
                continue

            line_no = int(m.group(1))
            code_line = m.group(2)

            # Check valid_lines
            valid = valid_lines.get(curr_file)
            if valid is not None and line_no not in valid:
                continue

            # 1. SQL Injection pattern
            if (
                re.search(
                    r"SELECT\s+.*\s+FROM\s+.*\s+WHERE.*(\+|\%|\.format|f['\"])",
                    code_line,
                    re.IGNORECASE,
                )
                or 'execute(f"SELECT' in code_line
                or "cursor.execute(query)" in code_line
                or "SELECT * FROM users WHERE id = '" in code_line
            ):
                f_id = generate_finding_id(
                    curr_file, Category.INJECTION, "SQL Injection via string concatenation"
                )
                findings.append(
                    Finding(
                        id=f_id,
                        file=curr_file,
                        start_line=line_no,
                        end_line=line_no,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        category=Category.INJECTION,
                        owasp="A03:2021 Injection",
                        cwe="CWE-89",
                        title="SQL Injection via dynamic query string formatting",
                        explanation="Untrusted user input is directly concatenated into a SQL statement, allowing attackers to execute arbitrary SQL commands.",
                        suggested_fix="Use parameterized queries or ORM query binding instead of string formatting.",
                        source=["claude"],
                    )
                )

            # 2. Hardcoded secret / API key pattern
            if (
                re.search(
                    r"(api_key|secret_key|password|token)\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
                    code_line,
                    re.IGNORECASE,
                )
                or "ghp_" in code_line
                or "sk-ant-" in code_line
            ):
                f_id = generate_finding_id(
                    curr_file, Category.SECRES, "Hardcoded sensitive credential"
                )
                findings.append(
                    Finding(
                        id=f_id,
                        file=curr_file,
                        start_line=line_no,
                        end_line=line_no,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category=Category.SECRES,
                        owasp="A02:2021 Cryptographic Failures",
                        cwe="CWE-798",
                        title="Hardcoded API secret or credential",
                        explanation="Sensitive credentials should never be committed into the codebase where they can be leaked or exposed.",
                        suggested_fix="Load secrets from secure environment variables or a secret management service.",
                        source=["claude"],
                    )
                )

            # 3. Missing Auth check / Broken Access Control
            if (
                "@app.route" in code_line
                and "admin" in code_line
                and "@login_required" not in chunk_content
            ):
                f_id = generate_finding_id(
                    curr_file, Category.AUTH, "Unprotected administrative route"
                )
                findings.append(
                    Finding(
                        id=f_id,
                        file=curr_file,
                        start_line=line_no,
                        end_line=line_no,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category=Category.AUTH,
                        owasp="A01:2021 Broken Access Control",
                        cwe="CWE-306",
                        title="Unprotected administrative endpoint",
                        explanation="Administrative routes must require authentication and appropriate role-based authorization.",
                        suggested_fix="Attach authentication and authorization decorators or middleware.",
                        source=["claude"],
                    )
                )

            # 4. Cross-Site Scripting (XSS)
            if (
                re.search(r"render_template_string\(.*(\+|request|user)", code_line)
                or "innerHTML = " in code_line
                or "dangerouslySetInnerHTML" in code_line
            ):
                f_id = generate_finding_id(
                    curr_file, Category.XSS, "Cross-Site Scripting vulnerability"
                )
                findings.append(
                    Finding(
                        id=f_id,
                        file=curr_file,
                        start_line=line_no,
                        end_line=line_no,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category=Category.XSS,
                        owasp="A03:2021 Injection",
                        cwe="CWE-79",
                        title="Cross-Site Scripting (XSS) via unescaped input",
                        explanation="Unsanitized user input rendered directly in HTML allows execution of arbitrary script in client browser.",
                        suggested_fix="Escape dynamic content or use template auto-escaping.",
                        source=["claude"],
                    )
                )

            # 5. Insecure Deserialization
            if "pickle.loads(" in code_line or "yaml.load(user_input" in code_line:
                f_id = generate_finding_id(
                    curr_file, Category.DESERIALIZATION, "Insecure deserialization"
                )
                findings.append(
                    Finding(
                        id=f_id,
                        file=curr_file,
                        start_line=line_no,
                        end_line=line_no,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        category=Category.DESERIALIZATION,
                        owasp="A08:2021 Software and Data Integrity Failures",
                        cwe="CWE-502",
                        title="Insecure deserialization of untrusted data",
                        explanation="Deserializing untrusted data with pickle or unsafe yaml loader can lead to arbitrary remote code execution.",
                        suggested_fix="Use safe serialization formats like JSON or yaml.safe_load.",
                        source=["claude"],
                    )
                )

        return findings

    def _scan_quality_patterns(
        self,
        chunk_content: str,
        valid_lines: dict[str, set[int]],
    ) -> list[Finding]:
        findings: list[Finding] = []
        lines = chunk_content.splitlines()

        curr_file = ""
        for line in lines:
            if line.startswith("### File: "):
                header = line.replace("### File: ", "").split()[0]
                curr_file = header
                continue

            m = re.match(r"^\s*(\d+)\s*\+\s*(.*)$", line)
            if not m or not curr_file:
                continue

            line_no = int(m.group(1))
            code_line = m.group(2)

            valid = valid_lines.get(curr_file)
            if valid is not None and line_no not in valid:
                continue

            # Broad bare except
            if re.match(r"^\s*except\s*:\s*(pass)?\s*$", code_line):
                f_id = generate_finding_id(
                    curr_file, Category.ERROR_HANDLING, "Bare except clause suppressing errors"
                )
                findings.append(
                    Finding(
                        id=f_id,
                        file=curr_file,
                        start_line=line_no,
                        end_line=line_no,
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        category=Category.ERROR_HANDLING,
                        title="Bare except clause catches SystemExit and KeyboardInterrupt",
                        explanation="Catching all exceptions indiscriminately can hide bugs and prevent process interruption.",
                        suggested_fix="Catch specific exception types such as Exception or custom error classes.",
                        source=["claude"],
                    )
                )

        return findings
