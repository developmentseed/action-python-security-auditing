"""Configuration contract — reads GitHub Action inputs from environment variables."""

from __future__ import annotations

from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All action inputs and GitHub context, read from env vars."""

    model_config = SettingsConfigDict(case_sensitive=False)

    # Tool selection
    tools: str = "bandit,pip-audit"

    # Bandit config — scan dirs and threshold are passed directly to lhoupert/bandit-action;
    # the Python module only reads the SARIF output and uses the threshold for reporting.
    bandit_severity_threshold: Literal["high", "medium", "low"] = "high"
    bandit_sarif_path: str = "results.sarif"

    # pip-audit config
    pip_audit_block_on: Literal["fixable", "all", "none"] = "fixable"

    # Package manager config
    package_manager: Literal["uv", "pip", "poetry", "pipenv", "requirements"] = "requirements"
    requirements_file: str = "requirements.txt"

    # PR comment config
    post_pr_comment: bool = True
    github_token: str = ""

    # GitHub context (standard env vars set by GitHub Actions)
    github_repository: str = ""
    github_run_id: str = ""
    pr_number: int | None = None
    github_event_name: str = ""
    github_head_ref: str = ""  # Branch name for PRs
    github_step_summary: str = ""  # Path to step summary file

    @property
    def enabled_tools(self) -> list[str]:
        return [t.strip() for t in self.tools.split(",") if t.strip()]

    @property
    def blocking_severities(self) -> list[str]:
        """All severities at or above the configured threshold."""
        all_severities = ["LOW", "MEDIUM", "HIGH"]
        threshold_idx = all_severities.index(self.bandit_severity_threshold.upper())
        return all_severities[threshold_idx:]
