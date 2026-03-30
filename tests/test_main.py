"""Tests for __main__.py orchestrator."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from python_security_auditing.__main__ import main

FIXTURES = Path(__file__).parent / "fixtures"


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

    uv_exc = subprocess.CalledProcessError(2, "uv", stderr="No uv.lock found")

    def mock_subprocess(cmd: list[str], **kwargs: object) -> MagicMock:
        if cmd[0] == "uv":
            raise uv_exc
        return MagicMock(returncode=0, stderr="", stdout="[]")

    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run", side_effect=mock_subprocess),
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

    uv_exc = subprocess.CalledProcessError(2, "uv", stderr="No uv.lock found")

    def mock_subprocess(cmd: list[str], **kwargs: object) -> MagicMock:
        if cmd[0] == "uv":
            raise uv_exc
        return MagicMock(returncode=0, stderr="", stdout="[]")

    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run", side_effect=mock_subprocess),
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

    uv_exc = subprocess.CalledProcessError(2, "uv", stderr="No uv.lock found")

    def mock_subprocess(cmd: list[str], **kwargs: object) -> MagicMock:
        if cmd[0] == "uv":
            raise uv_exc
        return MagicMock(returncode=0, stderr="", stdout="[]")

    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run", side_effect=mock_subprocess),
        patch("python_security_auditing.__main__.emit_annotations"),
        patch("python_security_auditing.__main__.upsert_pr_comment") as mock_comment,
    ):
        main()
    mock_comment.assert_not_called()


def test_main_succeeds_when_uv_lockfile_missing_and_no_bandit_issues(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text((FIXTURES / "bandit_clean.sarif").read_text())
    monkeypatch.setenv("PACKAGE_MANAGER", "uv")
    monkeypatch.setenv("TOOLS", "bandit,pip-audit")
    monkeypatch.setenv("BANDIT_SARIF_PATH", str(sarif_path))
    monkeypatch.chdir(tmp_path)

    uv_exc = subprocess.CalledProcessError(2, "uv", stderr="No uv.lock found")

    def mock_subprocess(cmd: list[str], **kwargs: object) -> MagicMock:
        if cmd[0] == "uv":
            raise uv_exc
        return MagicMock(returncode=0, stderr="", stdout="[]")

    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run", side_effect=mock_subprocess),
        patch("python_security_auditing.__main__.emit_annotations"),
    ):
        main()  # should return normally without calling sys.exit(1)


def test_main_fails_when_bandit_blocks_despite_missing_lockfile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text((FIXTURES / "bandit_issues.sarif").read_text())
    monkeypatch.setenv("PACKAGE_MANAGER", "uv")
    monkeypatch.setenv("TOOLS", "bandit,pip-audit")
    monkeypatch.setenv("BANDIT_SARIF_PATH", str(sarif_path))
    monkeypatch.setenv("BANDIT_SEVERITY_THRESHOLD", "high")
    monkeypatch.chdir(tmp_path)

    uv_exc = subprocess.CalledProcessError(2, "uv", stderr="No uv.lock found")

    def mock_subprocess(cmd: list[str], **kwargs: object) -> MagicMock:
        if cmd[0] == "uv":
            raise uv_exc
        return MagicMock(returncode=0, stderr="", stdout="[]")

    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run", side_effect=mock_subprocess),
        patch("python_security_auditing.__main__.emit_annotations"),
    ):
        with pytest.raises(SystemExit) as exc_info:
            main()
    assert exc_info.value.code == 1
