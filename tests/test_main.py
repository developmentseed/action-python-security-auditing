"""Tests for __main__.py orchestrator."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from python_security_auditing.__main__ import main

FIXTURES = Path(__file__).parent / "fixtures"


CLEAN_REPORT = '{"dependencies": [{"name": "requests", "version": "2.32.0", "vulns": []}]}'


def _fake_tools(bandit_sarif: str, uv_error: Exception | None = None) -> Any:
    """subprocess.run stand-in: bandit writes a fixture SARIF; uv export and pip-audit are clean."""

    def run(cmd: list[str], **kwargs: object) -> MagicMock:
        if cmd[1:3] == ["-m", "bandit"]:
            Path(cmd[cmd.index("-o") + 1]).write_text((FIXTURES / bandit_sarif).read_text())
        elif cmd[0] == "uv" and uv_error:
            raise uv_error
        return MagicMock(returncode=0, stderr="", stdout=CLEAN_REPORT)

    return run


def test_comment_on_never_never_calls_upsert(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """comment_on=never (default) must never call upsert_pr_comment, even with a token."""
    monkeypatch.setenv("PACKAGE_MANAGER", "uv")
    monkeypatch.setenv("TOOLS", "bandit,pip-audit")
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.chdir(tmp_path)

    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch(
            "python_security_auditing.runners.subprocess.run",
            side_effect=_fake_tools("bandit_issues.sarif"),
        ),
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
    monkeypatch.setenv("PACKAGE_MANAGER", "uv")
    monkeypatch.setenv("TOOLS", "bandit,pip-audit")
    monkeypatch.setenv("BANDIT_SEVERITY_THRESHOLD", "high")
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setenv("COMMENT_ON", "blocking")
    monkeypatch.chdir(tmp_path)

    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch(
            "python_security_auditing.runners.subprocess.run",
            side_effect=_fake_tools("bandit_issues.sarif"),
        ),
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
    monkeypatch.setenv("PACKAGE_MANAGER", "uv")
    monkeypatch.setenv("TOOLS", "bandit,pip-audit")
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setenv("COMMENT_ON", "blocking")
    monkeypatch.chdir(tmp_path)

    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch(
            "python_security_auditing.runners.subprocess.run",
            side_effect=_fake_tools("bandit_clean.sarif"),
        ),
        patch("python_security_auditing.__main__.emit_annotations"),
        patch("python_security_auditing.__main__.upsert_pr_comment") as mock_comment,
    ):
        main()
    mock_comment.assert_not_called()


def test_main_fails_closed_when_uv_export_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A failed export must fail the step and say so, not report 'No vulnerabilities found'."""
    summary_path = tmp_path / "summary.md"
    monkeypatch.setenv("PACKAGE_MANAGER", "uv")
    monkeypatch.setenv("TOOLS", "bandit,pip-audit")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_path))
    monkeypatch.chdir(tmp_path)
    # a report left by an earlier run must not be uploaded as this run's result
    (tmp_path / "pip-audit-report.json").write_text('{"dependencies": [], "fixes": []}')

    uv_exc = subprocess.CalledProcessError(2, "uv", stderr="No uv.lock found\nsecond line")
    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch(
            "python_security_auditing.runners.subprocess.run",
            side_effect=_fake_tools("bandit_clean.sarif", uv_exc),
        ),
    ):
        with pytest.raises(SystemExit) as exc_info:
            main()

    message = str(exc_info.value.code)  # a str code exits with status 1
    assert "pip-audit did NOT run" in message
    assert "uv export failed: No uv.lock found" in message
    summary = summary_path.read_text()
    assert "pip-audit did NOT run" in summary
    assert "No vulnerabilities found" not in summary
    out = capsys.readouterr().out
    assert "::error::pip-audit did NOT run: uv export failed: No uv.lock found%0Asecond line" in out
    assert not (tmp_path / "pip-audit-report.json").exists()


def test_main_reports_bandit_and_comments_when_pip_audit_cannot_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A failed audit must not hide bandit results or leave a stale PR comment."""
    summary_path = tmp_path / "summary.md"
    monkeypatch.setenv("PACKAGE_MANAGER", "uv")
    monkeypatch.setenv("TOOLS", "bandit,pip-audit")
    monkeypatch.setenv("BANDIT_SEVERITY_THRESHOLD", "high")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_path))
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setenv("COMMENT_ON", "blocking")
    monkeypatch.chdir(tmp_path)

    uv_exc = subprocess.CalledProcessError(2, "uv", stderr="No uv.lock found")
    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch(
            "python_security_auditing.runners.subprocess.run",
            side_effect=_fake_tools("bandit_issues.sarif", uv_exc),
        ),
        patch("python_security_auditing.__main__.upsert_pr_comment") as mock_comment,
    ):
        with pytest.raises(SystemExit) as exc_info:
            main()

    assert exc_info.value.code not in (None, 0)
    summary = summary_path.read_text()
    assert "B404" in summary  # bandit section still rendered
    assert "pip-audit did NOT run" in summary
    assert "::error file=src/app.py,line=2::[B404]" in capsys.readouterr().out
    mock_comment.assert_called_once()
    assert "pip-audit did NOT run" in mock_comment.call_args[0][0]


def test_main_reports_pip_audit_when_bandit_cannot_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A failed bandit run must fail the step and say so, and still report pip-audit."""
    summary_path = tmp_path / "summary.md"
    monkeypatch.setenv("PACKAGE_MANAGER", "uv")
    monkeypatch.setenv("TOOLS", "bandit,pip-audit")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_path))
    monkeypatch.chdir(tmp_path)

    def run(cmd: list[str], **kwargs: object) -> MagicMock:
        if cmd[1:3] == ["-m", "bandit"]:
            return MagicMock(returncode=2, stderr="ERROR\tMultiple .bandit files found", stdout="")
        return MagicMock(returncode=0, stderr="", stdout=CLEAN_REPORT)

    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run", side_effect=run),
    ):
        with pytest.raises(SystemExit) as exc_info:
            main()

    assert str(exc_info.value.code) == (
        "bandit did NOT run, so the code was NOT scanned.\n"
        "bandit failed (exit 2):\nERROR\tMultiple .bandit files found"
    )
    summary = summary_path.read_text()
    assert "bandit did NOT run" in summary
    assert "No issues found" not in summary
    assert "_Dependencies audited: 1, skipped: 0._" in summary  # pip-audit still reported
    assert "Blocking issues found" in summary
    out = capsys.readouterr().out
    assert "::error::bandit did NOT run: bandit failed (exit 2):%0AERROR" in out
    assert (tmp_path / "pip-audit-report.json").exists()
    assert not (tmp_path / "results.sarif").exists()


def test_main_fails_but_reports_findings_when_bandit_skips_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Files bandit could not scan block the job; the other files' findings are still shown."""
    summary_path = tmp_path / "summary.md"
    monkeypatch.setenv("TOOLS", "bandit")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_path))
    monkeypatch.chdir(tmp_path)
    sarif = json.loads((FIXTURES / "bandit_issues.sarif").read_text())
    notice = {
        "message": {"text": "syntax error while parsing AST from file"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/new.py"}}}],
    }
    sarif["runs"][0]["invocations"][0]["toolConfigurationNotifications"] = [notice]

    def run(cmd: list[str], **kwargs: object) -> MagicMock:
        Path(cmd[cmd.index("-o") + 1]).write_text(json.dumps(sarif))
        return MagicMock(returncode=0, stderr="", stdout="")

    with patch("python_security_auditing.runners.subprocess.run", side_effect=run):
        with pytest.raises(SystemExit) as exc_info:
            main()

    assert exc_info.value.code == 1
    summary = summary_path.read_text()
    assert "bandit could not scan 1 file(s)" in summary
    assert "B404" in summary
    assert "did NOT run" not in summary
    out = capsys.readouterr().out
    assert "::error::bandit could not scan 1 file(s)" in out
    assert "::error file=src/app.py,line=2::[B404]" in out
    assert not (tmp_path / "results.sarif").exists()
