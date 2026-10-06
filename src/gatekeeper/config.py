"""Configuration schema and loader for Gatekeeper AI."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

from gatekeeper.models import Confidence


class ModelConfig(BaseModel):
    provider: str = "anthropic"
    name: str = "claude-sonnet-latest"
    max_output_tokens: int = 4096
    temperature: float = 0.0


class ReviewConfig(BaseModel):
    passes: list[str] = Field(default_factory=lambda: ["security", "quality"])
    target_branches: list[str] = Field(default_factory=lambda: ["qa", "main"])
    include: list[str] = Field(default_factory=lambda: ["**/*"])
    exclude: list[str] = Field(
        default_factory=lambda: [
            "**/*.lock",
            "**/dist/**",
            "**/vendor/**",
            "**/*.min.js",
            "**/migrations/**",
            "**/.venv/**",
            "**/node_modules/**",
        ]
    )
    max_files: int = 60
    max_diff_lines: int = 3000
    context_lines: int = 20
    language_hints: str = "auto"
    custom_rules: list[str] = Field(default_factory=list)


class BudgetConfig(BaseModel):
    max_input_tokens_per_run: int = 200000
    on_budget_exceeded: Literal["warn", "fail", "skip_remaining"] = "warn"


class SemgrepConfig(BaseModel):
    enabled: bool = True
    config: str = "p/owasp-top-ten"


class BanditConfig(BaseModel):
    enabled: bool | Literal["auto"] = "auto"


class GitleaksConfig(BaseModel):
    enabled: bool = True


class SonarQubeConfig(BaseModel):
    enabled: bool = False
    url_env: str = "SONAR_HOST_URL"
    token_env: str = "SONAR_TOKEN"
    project_key: str = ""


class ScannersConfig(BaseModel):
    semgrep: SemgrepConfig = Field(default_factory=SemgrepConfig)
    bandit: BanditConfig = Field(default_factory=BanditConfig)
    gitleaks: GitleaksConfig = Field(default_factory=GitleaksConfig)
    sonarqube: SonarQubeConfig = Field(default_factory=SonarQubeConfig)
    triage_with_llm: bool = True


class FailOnConfig(BaseModel):
    critical: int = 1
    high: int = 1
    medium: int = 10
    low: int = 999999
    info: int = 999999


class GateConfig(BaseModel):
    fail_on: FailOnConfig = Field(default_factory=FailOnConfig)
    min_confidence: Confidence = Confidence.MEDIUM
    fail_on_scanner_error: bool = False
    fail_on_llm_error: bool = True


class SuppressionsConfig(BaseModel):
    inline_marker: str = "gatekeeper-ignore"
    baseline_file: str = ".gatekeeper/baseline.json"


class OutputsConfig(BaseModel):
    pr_comment: Literal["off", "summary", "summary_and_inline"] = "summary_and_inline"
    max_inline_comments: int = 25
    formats: list[str] = Field(default_factory=lambda: ["markdown", "html", "json", "sarif"])
    output_dir: str = "gatekeeper-report"


class SlackConfig(BaseModel):
    webhook_env: str = "GK_SLACK_WEBHOOK"


class TeamsConfig(BaseModel):
    webhook_env: str = "GK_TEAMS_WEBHOOK"


class EmailConfig(BaseModel):
    smtp_host_env: str = "GK_SMTP_HOST"
    smtp_user_env: str = "GK_SMTP_USER"
    smtp_password_env: str = "GK_SMTP_PASSWORD"
    from_address: str = Field(default="gatekeeper@example.com", alias="from")
    to: list[str] = Field(default_factory=lambda: ["qa-lead@example.com"])

    model_config = {"populate_by_name": True}


class NotifyConfig(BaseModel):
    on: list[Literal["fail", "error", "pass"]] = Field(
        default_factory=lambda: ["fail", "error"]  # type: ignore[arg-type]
    )
    slack: SlackConfig = Field(default_factory=SlackConfig)
    teams: TeamsConfig = Field(default_factory=TeamsConfig)
    email: EmailConfig = Field(default_factory=EmailConfig)


class GatekeeperConfig(BaseModel):
    version: int = 1
    model: ModelConfig = Field(default_factory=ModelConfig)
    review: ReviewConfig = Field(default_factory=ReviewConfig)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    scanners: ScannersConfig = Field(default_factory=ScannersConfig)
    gate: GateConfig = Field(default_factory=GateConfig)
    suppressions: SuppressionsConfig = Field(default_factory=SuppressionsConfig)
    outputs: OutputsConfig = Field(default_factory=OutputsConfig)
    notify: NotifyConfig = Field(default_factory=NotifyConfig)

    def compute_hash(self) -> str:
        """Return a SHA256 hex digest of the normalized config JSON."""
        data = self.model_dump_json()
        return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16]


DEFAULT_CONFIG_YAML = """# gatekeeper.yml - Gatekeeper AI configuration
version: 1

model:
  provider: anthropic
  name: claude-sonnet-latest
  max_output_tokens: 4096
  temperature: 0.0

review:
  passes: [security, quality]
  target_branches: [qa, main]
  include: ["**/*"]
  exclude: ["**/*.lock", "**/dist/**", "**/vendor/**", "**/*.min.js", "**/migrations/**"]
  max_files: 60
  max_diff_lines: 3000
  context_lines: 20
  language_hints: auto
  custom_rules:
    - "All SQL must use parameterised queries."
    - "No logging of personal data (email, phone, tax code)."

budget:
  max_input_tokens_per_run: 200000
  on_budget_exceeded: warn

scanners:
  semgrep: { enabled: true, config: "p/owasp-top-ten" }
  bandit: { enabled: auto }
  gitleaks: { enabled: true }
  sonarqube: { enabled: false, url_env: SONAR_HOST_URL, token_env: SONAR_TOKEN, project_key: "" }
  triage_with_llm: true

gate:
  fail_on:
    critical: 1
    high: 1
    medium: 10
  min_confidence: medium
  fail_on_scanner_error: false
  fail_on_llm_error: true

suppressions:
  inline_marker: "gatekeeper-ignore"
  baseline_file: .gatekeeper/baseline.json

outputs:
  pr_comment: summary_and_inline
  max_inline_comments: 25
  formats: [markdown, html, json, sarif]
  output_dir: gatekeeper-report

notify:
  on: [fail, error]
  slack: { webhook_env: GK_SLACK_WEBHOOK }
  teams: { webhook_env: GK_TEAMS_WEBHOOK }
  email:
    smtp_host_env: GK_SMTP_HOST
    smtp_user_env: GK_SMTP_USER
    smtp_password_env: GK_SMTP_PASSWORD
    from: gatekeeper@example.com
    to: [qa-lead@example.com]
"""

STRICT_PRESET_YAML = DEFAULT_CONFIG_YAML.replace(
    """  fail_on:
    critical: 1
    high: 1
    medium: 10""",
    """  fail_on:
    critical: 1
    high: 1
    medium: 5""",
)

LENIENT_PRESET_YAML = DEFAULT_CONFIG_YAML.replace(
    """  fail_on:
    critical: 1
    high: 1
    medium: 10""",
    """  fail_on:
    critical: 1
    high: 999
    medium: 999""",
)


def load_config(config_path: Path | str | None = None) -> GatekeeperConfig:
    """Load and validate configuration from YAML file or return default."""
    if config_path is None:
        target = Path("gatekeeper.yml")
        if not target.exists():
            target = Path(".gatekeeper.yml")
            if not target.exists():
                return GatekeeperConfig()
    else:
        target = Path(config_path)
        if not target.exists():
            raise FileNotFoundError(f"Configuration file not found: {target}")

    with open(target, encoding="utf-8") as f:
        content = yaml.safe_load(f)

    if not isinstance(content, dict):
        raise ValueError(f"Invalid YAML structure in {target}, expected mapping")

    return GatekeeperConfig.model_validate(content)
