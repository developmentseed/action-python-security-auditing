"""Tests for pr_comment.py — comment marker and upsert logic."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from python_security_auditing.pr_comment import comment_marker, upsert_pr_comment
from python_security_auditing.settings import Settings

# ---------------------------------------------------------------------------
# comment_marker()
# ---------------------------------------------------------------------------


def test_comment_marker_empty() -> None:
    assert comment_marker("") == "<!-- security-scan-results -->"


def test_comment_marker_with_workflow() -> None:
    assert comment_marker("my-workflow") == "<!-- security-scan-results::my-workflow -->"


def test_comment_marker_backward_compat() -> None:
    """Empty workflow produces the original marker (no :: suffix)."""
    assert "::" not in comment_marker("")


# ---------------------------------------------------------------------------
# upsert_pr_comment() — guard clauses
# ---------------------------------------------------------------------------


def test_upsert_skips_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POST_PR_COMMENT", "false")
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    s = Settings()
    with patch("python_security_auditing.pr_comment.subprocess.run") as mock_run:
        upsert_pr_comment("# Report", s)
        mock_run.assert_not_called()


def test_upsert_skips_when_no_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POST_PR_COMMENT", "true")
    monkeypatch.setenv("GITHUB_TOKEN", "")
    s = Settings()
    with patch("python_security_auditing.pr_comment.subprocess.run") as mock_run:
        upsert_pr_comment("# Report", s)
        mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# upsert_pr_comment() — creates or updates using workflow-specific marker
# ---------------------------------------------------------------------------


def test_upsert_creates_new_comment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POST_PR_COMMENT", "true")
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
    monkeypatch.setenv("PR_NUMBER", "42")
    monkeypatch.setenv("GITHUB_WORKFLOW", "my-workflow")
    s = Settings()

    list_response = MagicMock(returncode=0, stdout=json.dumps([]))
    with (
        patch("python_security_auditing.pr_comment.shutil.which", side_effect=lambda exe: exe),
        patch(
            "python_security_auditing.pr_comment.subprocess.run",
            side_effect=[list_response, MagicMock()],
        ) as mock_run,
    ):
        upsert_pr_comment("# Report", s)

        create_call = mock_run.call_args_list[1]
        cmd: list[str] = create_call[0][0]
        assert cmd[:3] == ["gh", "pr", "comment"]
        body = cmd[cmd.index("--body") + 1]
        assert "<!-- security-scan-results::my-workflow -->" in body


def test_upsert_updates_existing_comment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POST_PR_COMMENT", "true")
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
    monkeypatch.setenv("PR_NUMBER", "42")
    monkeypatch.setenv("GITHUB_WORKFLOW", "my-workflow")
    s = Settings()

    existing = [{"id": 99, "body": "<!-- security-scan-results::my-workflow -->\nold"}]
    list_response = MagicMock(returncode=0, stdout=json.dumps(existing))
    with (
        patch("python_security_auditing.pr_comment.shutil.which", side_effect=lambda exe: exe),
        patch(
            "python_security_auditing.pr_comment.subprocess.run",
            side_effect=[list_response, MagicMock()],
        ) as mock_run,
    ):
        upsert_pr_comment("# Report", s)

        patch_call = mock_run.call_args_list[1]
        cmd: list[str] = patch_call[0][0]
        assert "PATCH" in cmd
        assert "comments/99" in " ".join(cmd)


def test_upsert_does_not_match_different_workflow(monkeypatch: pytest.MonkeyPatch) -> None:
    """A comment from workflow-b must not be reused by workflow-a."""
    monkeypatch.setenv("POST_PR_COMMENT", "true")
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
    monkeypatch.setenv("PR_NUMBER", "42")
    monkeypatch.setenv("GITHUB_WORKFLOW", "workflow-a")
    s = Settings()

    other_workflow_comment = [{"id": 99, "body": "<!-- security-scan-results::workflow-b -->\nold"}]
    list_response = MagicMock(returncode=0, stdout=json.dumps(other_workflow_comment))
    with (
        patch("python_security_auditing.pr_comment.shutil.which", side_effect=lambda exe: exe),
        patch(
            "python_security_auditing.pr_comment.subprocess.run",
            side_effect=[list_response, MagicMock()],
        ) as mock_run,
    ):
        upsert_pr_comment("# Report", s)

        # Must create a new comment, not PATCH the existing one
        create_call = mock_run.call_args_list[1]
        cmd: list[str] = create_call[0][0]
        assert cmd[:3] == ["gh", "pr", "comment"]


def test_upsert_raises_when_gh_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POST_PR_COMMENT", "true")
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
    monkeypatch.setenv("PR_NUMBER", "42")
    s = Settings()
    with patch("python_security_auditing.pr_comment.shutil.which", return_value=None):
        with pytest.raises(FileNotFoundError, match="gh"):
            upsert_pr_comment("# Report", s)
