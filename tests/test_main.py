"""Tests for __main__.py orchestrator."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from python_security_auditing.__main__ import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_main_succeeds_when_uv_lockfile_missing_and_no_bandit_issues(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text((FIXTURES / "bandit_clean.sarif").read_text())
    monkeypatch.setenv("PACKAGE_MANAGER", "uv")
    monkeypatch.setenv("TOOLS", "bandit,pip-audit")
    monkeypatch.setenv("BANDIT_SARIF_PATH", str(sarif_path))
    monkeypatch.setenv("POST_PR_COMMENT", "false")
    monkeypatch.chdir(tmp_path)

    uv_exc = subprocess.CalledProcessError(2, "uv", stderr="No uv.lock found")

    def mock_subprocess(cmd: list[str], **kwargs: object) -> MagicMock:
        if cmd[0] == "uv":
            raise uv_exc
        return MagicMock(returncode=0, stderr="", stdout="[]")

    with patch("python_security_auditing.runners.subprocess.run", side_effect=mock_subprocess):
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
    monkeypatch.setenv("POST_PR_COMMENT", "false")
    monkeypatch.chdir(tmp_path)

    uv_exc = subprocess.CalledProcessError(2, "uv", stderr="No uv.lock found")

    def mock_subprocess(cmd: list[str], **kwargs: object) -> MagicMock:
        if cmd[0] == "uv":
            raise uv_exc
        return MagicMock(returncode=0, stderr="", stdout="[]")

    with patch("python_security_auditing.runners.subprocess.run", side_effect=mock_subprocess):
        with pytest.raises(SystemExit) as exc_info:
            main()
    assert exc_info.value.code == 1
