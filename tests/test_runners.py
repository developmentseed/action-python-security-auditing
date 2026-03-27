"""Tests for runners.py — tool invocation and package manager adapter."""

from __future__ import annotations

import json
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

    with patch("python_security_auditing.runners.subprocess.run") as mock_run:
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
    with patch("python_security_auditing.runners.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=freeze_output)
        result = generate_requirements(s)

    cmd = mock_run.call_args[0][0]
    assert cmd == ["pip", "freeze"]
    assert result.read_text() == freeze_output


def test_poetry_mode_calls_poetry_export(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PACKAGE_MANAGER", "poetry")
    s = Settings()

    with patch("python_security_auditing.runners.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        result = generate_requirements(s)

    cmd = mock_run.call_args[0][0]
    assert cmd[0] == "poetry"
    assert "export" in cmd
    assert str(result).endswith("-requirements.txt")


def test_pipenv_mode_calls_pipenv_requirements(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PACKAGE_MANAGER", "pipenv")
    s = Settings()

    pipenv_output = "requests==2.31.0\n"
    with patch("python_security_auditing.runners.subprocess.run") as mock_run:
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

    with patch("python_security_auditing.runners.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stderr="", stdout=fixture_text)
        report = run_pip_audit(Path("requirements.txt"))

    assert len(report) == 2
    assert report[0]["name"] == "requests"
    assert (tmp_path / "pip-audit-report.json").exists()


def test_run_pip_audit_returns_empty_on_no_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    with patch("python_security_auditing.runners.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
        report = run_pip_audit(Path("requirements.txt"))

    assert report == []


def test_run_pip_audit_uses_requirements_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    req_path = tmp_path / "custom-reqs.txt"

    with patch("python_security_auditing.runners.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="[]")
        run_pip_audit(req_path)

    cmd = mock_run.call_args[0][0]
    assert str(req_path) in cmd
    assert "-f" in cmd
    assert "json" in cmd
