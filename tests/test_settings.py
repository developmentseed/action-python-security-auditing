"""Tests for settings.py — env var parsing and computed properties."""

import pytest
from pydantic import ValidationError
from python_security_auditing.settings import Settings


def test_defaults() -> None:
    s = Settings()
    assert s.tools == "bandit,pip-audit"
    assert s.bandit_severity_threshold == "high"
    assert s.bandit_sarif_path == "results.sarif"
    assert s.pip_audit_block_on == "fixable"
    assert s.package_manager == "requirements"
    assert s.requirements_file == "requirements.txt"
    assert s.post_pr_comment is True
    assert s.github_token == ""


def test_enabled_tools_default() -> None:
    s = Settings()
    assert s.enabled_tools == ["bandit", "pip-audit"]


def test_enabled_tools_single(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TOOLS", "bandit")
    s = Settings()
    assert s.enabled_tools == ["bandit"]


def test_enabled_tools_custom(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TOOLS", "pip-audit")
    s = Settings()
    assert s.enabled_tools == ["pip-audit"]


def test_enabled_tools_whitespace(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TOOLS", " bandit , pip-audit ")
    s = Settings()
    assert s.enabled_tools == ["bandit", "pip-audit"]


def test_bandit_sarif_path_custom(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BANDIT_SARIF_PATH", "/workspace/results.sarif")
    s = Settings()
    assert s.bandit_sarif_path == "/workspace/results.sarif"


def test_blocking_severities_high() -> None:
    s = Settings()
    assert s.blocking_severities == ["HIGH"]


def test_blocking_severities_medium(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BANDIT_SEVERITY_THRESHOLD", "medium")
    s = Settings()
    assert s.blocking_severities == ["MEDIUM", "HIGH"]


def test_blocking_severities_low(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BANDIT_SEVERITY_THRESHOLD", "low")
    s = Settings()
    assert s.blocking_severities == ["LOW", "MEDIUM", "HIGH"]


def test_pr_number_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PR_NUMBER", "42")
    s = Settings()
    assert s.pr_number == 42


def test_pr_number_empty_string(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PR_NUMBER", "")
    s = Settings()
    assert s.pr_number is None


def test_post_pr_comment_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POST_PR_COMMENT", "false")
    s = Settings()
    assert s.post_pr_comment is False


def test_github_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
    monkeypatch.setenv("GITHUB_RUN_ID", "12345")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_HEAD_REF", "feature/my-branch")
    s = Settings()
    assert s.github_repository == "org/repo"
    assert s.github_run_id == "12345"
    assert s.github_event_name == "pull_request"
    assert s.github_head_ref == "feature/my-branch"


def test_github_workflow(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_WORKFLOW", "CI")
    s = Settings()
    assert s.github_workflow == "CI"


# ---------------------------------------------------------------------------
# Path traversal validation
# ---------------------------------------------------------------------------


def test_bandit_sarif_path_rejects_traversal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BANDIT_SARIF_PATH", "../etc/passwd")
    with pytest.raises(ValidationError):
        Settings()


def test_requirements_file_rejects_traversal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REQUIREMENTS_FILE", "../../etc/shadow")
    with pytest.raises(ValidationError):
        Settings()


def test_github_step_summary_rejects_traversal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", "/tmp/../../etc/hosts")
    with pytest.raises(ValidationError):
        Settings()


# ---------------------------------------------------------------------------
# github_repository format validation
# ---------------------------------------------------------------------------


def test_github_repository_accepts_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "my-org/my-repo")
    s = Settings()
    assert s.github_repository == "my-org/my-repo"


def test_github_repository_rejects_traversal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "../../secret-org/secret-repo")
    with pytest.raises(ValidationError):
        Settings()


def test_github_repository_rejects_extra_slashes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo/extra")
    with pytest.raises(ValidationError):
        Settings()


def test_github_repository_empty_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "")
    s = Settings()
    assert s.github_repository == ""


# ---------------------------------------------------------------------------
# github_run_id numeric validation
# ---------------------------------------------------------------------------


def test_github_run_id_accepts_numeric(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_RUN_ID", "12345678")
    s = Settings()
    assert s.github_run_id == "12345678"


def test_github_run_id_rejects_non_numeric(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_RUN_ID", "123; rm -rf /")
    with pytest.raises(ValidationError):
        Settings()


def test_github_run_id_empty_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_RUN_ID", "")
    s = Settings()
    assert s.github_run_id == ""


# ---------------------------------------------------------------------------
# github_head_ref branch name validation
# ---------------------------------------------------------------------------


def test_github_head_ref_accepts_dependabot_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_HEAD_REF", "dependabot/pip/requests-2.32.0")
    s = Settings()
    assert s.github_head_ref == "dependabot/pip/requests-2.32.0"


def test_github_head_ref_empty_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_HEAD_REF", "")
    s = Settings()
    assert s.github_head_ref == ""


def test_github_head_ref_rejects_semicolon(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_HEAD_REF", "main; rm -rf /")
    with pytest.raises(ValidationError):
        Settings()


def test_github_head_ref_rejects_newline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_HEAD_REF", "feature/branch\ninjected")
    with pytest.raises(ValidationError):
        Settings()
