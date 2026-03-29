"""Tests for runners.py — tool invocation and package manager adapter."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from python_security_auditing.runners import generate_requirements, read_bandit_sarif, run_pip_audit
from python_security_auditing.settings import Settings

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# generate_requirements
# ---------------------------------------------------------------------------


def test_requirements_mode_returns_configured_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PACKAGE_MANAGER", "requirements")
    monkeypatch.setenv("REQUIREMENTS_FILE", "custom-requirements.txt")
    s = Settings()
    assert generate_requirements(s) == Path("custom-requirements.txt")


def test_uv_mode_calls_uv_export(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("PACKAGE_MANAGER", "uv")
    s = Settings()

    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=0)
        result = generate_requirements(s)

    cmd = mock_run.call_args[0][0]
    assert cmd[0] == "uv"
    assert "export" in cmd
    assert "--format" in cmd
    assert "requirements-txt" in cmd
    assert str(result).endswith("-requirements.txt")


def test_pip_mode_calls_pip_freeze(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PACKAGE_MANAGER", "pip")
    s = Settings()

    freeze_output = "requests==2.31.0\n"
    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=0, stdout=freeze_output)
        result = generate_requirements(s)

    cmd = mock_run.call_args[0][0]
    assert cmd == ["pip", "freeze"]
    assert result.read_text() == freeze_output


def test_poetry_mode_calls_poetry_export(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PACKAGE_MANAGER", "poetry")
    s = Settings()

    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=0)
        result = generate_requirements(s)

    assert mock_run.call_count == 2
    plugin_cmd = mock_run.call_args_list[0][0][0]
    assert plugin_cmd == ["poetry", "self", "add", "poetry-plugin-export"]
    export_cmd = mock_run.call_args_list[1][0][0]
    assert export_cmd[0] == "poetry"
    assert "export" in export_cmd
    assert str(result).endswith("-requirements.txt")


def test_pipenv_mode_calls_pipenv_requirements(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PACKAGE_MANAGER", "pipenv")
    s = Settings()

    pipenv_output = "requests==2.31.0\n"
    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=0, stdout=pipenv_output)
        result = generate_requirements(s)

    cmd = mock_run.call_args[0][0]
    assert cmd == ["pipenv", "requirements"]
    assert result.read_text() == pipenv_output


# ---------------------------------------------------------------------------
# read_bandit_sarif
# ---------------------------------------------------------------------------


def test_read_bandit_sarif_parses_findings(tmp_path: Path) -> None:
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text((FIXTURES / "bandit_issues.sarif").read_text())
    report = read_bandit_sarif(sarif_path)

    assert len(report["results"]) == 2
    assert report["results"][0]["issue_severity"] == "HIGH"
    assert report["results"][0]["issue_confidence"] == "HIGH"
    assert report["results"][0]["test_id"] == "B404"
    assert report["results"][0]["filename"] == "src/app.py"
    assert report["results"][0]["line_number"] == 2
    assert report["results"][1]["issue_severity"] == "MEDIUM"


def test_read_bandit_sarif_returns_empty_on_missing_file(tmp_path: Path) -> None:
    report = read_bandit_sarif(tmp_path / "results.sarif")
    assert report["results"] == []
    assert report["errors"] == []


def test_read_bandit_sarif_returns_empty_on_clean_sarif(tmp_path: Path) -> None:
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text((FIXTURES / "bandit_clean.sarif").read_text())
    report = read_bandit_sarif(sarif_path)
    assert report["results"] == []


def test_read_bandit_sarif_falls_back_to_level_mapping(tmp_path: Path) -> None:
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "B999",
                                "level": "warning",
                                "message": {"text": "test issue"},
                                "locations": [],
                                "properties": {},
                            }
                        ]
                    }
                ],
            }
        )
    )
    report = read_bandit_sarif(sarif_path)
    assert report["results"][0]["issue_severity"] == "MEDIUM"


# ---------------------------------------------------------------------------
# run_pip_audit
# ---------------------------------------------------------------------------


def test_run_pip_audit_parses_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    # pip-audit 2.7+ wraps output in {"dependencies": [...], "fixes": [...]}
    deps = json.loads((FIXTURES / "pip_audit_fixable.json").read_text())
    fixture_text = json.dumps({"dependencies": deps, "fixes": []})

    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=1, stderr="", stdout=fixture_text)
        report = run_pip_audit(Path("requirements.txt"))

    assert isinstance(report, list)
    assert len(report) == 2
    assert report[0]["name"] == "requests"
    assert (tmp_path / "pip-audit-report.json").exists()


def test_run_pip_audit_returns_empty_on_no_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
        report = run_pip_audit(Path("requirements.txt"))

    assert report == []


def test_run_pip_audit_uses_requirements_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    req_path = tmp_path / "custom-reqs.txt"

    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="[]")
        run_pip_audit(req_path)

    cmd = mock_run.call_args[0][0]
    assert str(req_path) in cmd
    assert "-f" in cmd
    assert "json" in cmd


def test_run_pip_audit_command_includes_no_deps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="[]")
        run_pip_audit(Path("requirements.txt"))
    cmd = mock_run.call_args[0][0]
    assert "--no-deps" in cmd


# ---------------------------------------------------------------------------
# generate_requirements — missing lockfile handling
# ---------------------------------------------------------------------------


def test_generate_requirements_uv_returns_empty_on_missing_lockfile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PACKAGE_MANAGER", "uv")
    s = Settings()
    exc = subprocess.CalledProcessError(2, "uv", stderr="No uv.lock found")
    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run", side_effect=exc),
    ):
        result = generate_requirements(s)
    assert result.exists()
    assert result.stat().st_size == 0


def test_generate_requirements_poetry_returns_empty_on_missing_lockfile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PACKAGE_MANAGER", "poetry")
    s = Settings()
    export_exc = subprocess.CalledProcessError(1, "poetry", stderr="poetry.lock not found")
    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run") as mock_run,
    ):
        # self add uses check=False so a non-zero return is silently ignored;
        # export raises CalledProcessError to simulate a missing lockfile
        mock_run.side_effect = [MagicMock(returncode=1), export_exc]
        result = generate_requirements(s)
    assert result.exists()
    assert result.stat().st_size == 0


def test_generate_requirements_pipenv_returns_empty_on_missing_lockfile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PACKAGE_MANAGER", "pipenv")
    s = Settings()
    exc = subprocess.CalledProcessError(1, "pipenv", stderr="Pipfile.lock not found")
    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run", side_effect=exc),
    ):
        result = generate_requirements(s)
    assert result.exists()
    assert result.stat().st_size == 0


def test_generate_requirements_uv_warns_on_missing_lockfile(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("PACKAGE_MANAGER", "uv")
    s = Settings()
    exc = subprocess.CalledProcessError(2, "uv", stderr="No uv.lock found")
    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run", side_effect=exc),
    ):
        generate_requirements(s)
    assert "uv export failed" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# generate_requirements / run_pip_audit — tool-not-found handling
# ---------------------------------------------------------------------------


def test_generate_requirements_raises_when_tool_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PACKAGE_MANAGER", "uv")
    s = Settings()
    with patch("python_security_auditing.runners.shutil.which", return_value=None):
        with pytest.raises(FileNotFoundError, match="uv"):
            generate_requirements(s)


def test_run_pip_audit_raises_when_tool_not_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    with patch("python_security_auditing.runners.shutil.which", return_value=None):
        with pytest.raises(FileNotFoundError, match="pip-audit"):
            run_pip_audit(Path("requirements.txt"))
