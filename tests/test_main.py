"""Tests for __main__.py orchestrator."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from python_security_auditing.__main__ import main

FIXTURES = Path(__file__).parent / "fixtures"


def _clean_audit(cmd: list[str], **kwargs: object) -> MagicMock:
    """uv export succeeds and pip-audit reports no vulnerabilities."""
    return MagicMock(returncode=0, stderr="", stdout='{"dependencies": [], "fixes": []}')


def _make_sarif_mock(sarif_content: str, pip_stdout: str = "[]") -> object:
    """Return a mock_subprocess factory that feeds a SARIF file and pip-audit output."""

    def mock_subprocess(cmd: list[str], **kwargs: object) -> MagicMock:
        return MagicMock(returncode=0, stderr="", stdout=pip_stdout)

    return mock_subprocess


def test_comment_on_never_never_calls_upsert(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """comment_on=never (default) must never call upsert_pr_comment, even with a token."""
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text((FIXTURES / "bandit_issues.sarif").read_text())
    monkeypatch.setenv("PACKAGE_MANAGER", "uv")
    monkeypatch.setenv("TOOLS", "bandit,pip-audit")
    monkeypatch.setenv("BANDIT_SARIF_PATH", str(sarif_path))
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.chdir(tmp_path)

    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run", side_effect=_clean_audit),
        patch("python_security_auditing.__main__.emit_annotations"),
        patch("python_security_auditing.__main__.upsert_pr_comment") as mock_comment,
    ):
        with pytest.raises(SystemExit):
            main()
    mock_comment.assert_not_called()


def test_comment_on_blocking_calls_upsert_when_blocking(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """comment_on=blocking must call upsert_pr_comment when blocking issues exist."""
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text((FIXTURES / "bandit_issues.sarif").read_text())
    monkeypatch.setenv("PACKAGE_MANAGER", "uv")
    monkeypatch.setenv("TOOLS", "bandit,pip-audit")
    monkeypatch.setenv("BANDIT_SARIF_PATH", str(sarif_path))
    monkeypatch.setenv("BANDIT_SEVERITY_THRESHOLD", "high")
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setenv("COMMENT_ON", "blocking")
    monkeypatch.chdir(tmp_path)

    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run", side_effect=_clean_audit),
        patch("python_security_auditing.__main__.emit_annotations"),
        patch("python_security_auditing.__main__.upsert_pr_comment") as mock_comment,
    ):
        with pytest.raises(SystemExit):
            main()
    mock_comment.assert_called_once()


def test_comment_on_blocking_skips_upsert_when_clean(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """comment_on=blocking must not call upsert_pr_comment when no blocking issues."""
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text((FIXTURES / "bandit_clean.sarif").read_text())
    monkeypatch.setenv("PACKAGE_MANAGER", "uv")
    monkeypatch.setenv("TOOLS", "bandit,pip-audit")
    monkeypatch.setenv("BANDIT_SARIF_PATH", str(sarif_path))
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setenv("COMMENT_ON", "blocking")
    monkeypatch.chdir(tmp_path)

    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run", side_effect=_clean_audit),
        patch("python_security_auditing.__main__.emit_annotations"),
        patch("python_security_auditing.__main__.upsert_pr_comment") as mock_comment,
    ):
        main()
    mock_comment.assert_not_called()


def test_main_fails_closed_when_uv_export_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A failed export must fail the step and say so, not report 'No vulnerabilities found'."""
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text((FIXTURES / "bandit_clean.sarif").read_text())
    summary_path = tmp_path / "summary.md"
    monkeypatch.setenv("PACKAGE_MANAGER", "uv")
    monkeypatch.setenv("TOOLS", "bandit,pip-audit")
    monkeypatch.setenv("BANDIT_SARIF_PATH", str(sarif_path))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_path))
    monkeypatch.chdir(tmp_path)

    uv_exc = subprocess.CalledProcessError(2, "uv", stderr="No uv.lock found")
    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run", side_effect=uv_exc),
        patch("python_security_auditing.__main__.emit_annotations"),
    ):
        with pytest.raises(SystemExit) as exc_info:
            main()

    message = str(exc_info.value.code)  # a str code exits with status 1
    assert "pip-audit did NOT run" in message
    assert "uv export failed: No uv.lock found" in message
    summary = summary_path.read_text()
    assert "pip-audit did NOT run" in summary
    assert "No vulnerabilities found" not in summary
