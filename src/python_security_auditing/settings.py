"""Configuration contract — reads GitHub Action inputs from environment variables."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All action inputs and GitHub context, read from env vars."""

    model_config = SettingsConfigDict(case_sensitive=False)

    # Debug mode — enabled via INPUT_DEBUG=true or RUNNER_DEBUG=1 (GitHub re-run with debug logging)
    input_debug: bool = False
    runner_debug: bool = False

    @field_validator("runner_debug", mode="before")
    @classmethod
    def _runner_debug_from_int(cls, v: object) -> object:
        # GitHub sets RUNNER_DEBUG="1" when enabled; it may also be "" when not set
        if v == "" or v == "0":
            return False
        return v

    @property
    def debug(self) -> bool:
        return self.input_debug or self.runner_debug

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

    @field_validator("pr_number", mode="before")
    @classmethod
    def _empty_str_to_none(cls, v: object) -> object:
        if v == "":
            return None
        return v

    @field_validator("bandit_sarif_path", "requirements_file", "github_step_summary", mode="after")
    @classmethod
    def _no_path_traversal(cls, v: str) -> str:
        if v and ".." in Path(v).parts:
            raise ValueError(f"Path traversal not allowed: {v!r}")
        return v

    @field_validator("github_repository", mode="after")
    @classmethod
    def _validate_repository_format(cls, v: str) -> str:
        if not v:
            return v
        if ".." in v or v.startswith("/") or v.count("/") != 1:
            raise ValueError(f"github_repository must be 'owner/repo' format, got: {v!r}")
        return v

    @field_validator("github_run_id", mode="after")
    @classmethod
    def _validate_run_id(cls, v: str) -> str:
        if v and not v.isdigit():
            raise ValueError(f"github_run_id must be numeric, got: {v!r}")
        return v

    github_head_ref: str = ""  # Branch name for PRs

    @field_validator("github_head_ref", mode="after")
    @classmethod
    def _validate_head_ref(cls, v: str) -> str:
        if v and not re.fullmatch(r"[a-zA-Z0-9._/\-]+", v):
            raise ValueError(
                f"github_head_ref contains invalid characters for a branch name: {v!r}"
            )
        return v

    github_workflow: str = ""  # Name of the running workflow
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
