"""Tests for runners.py — tool invocation and package manager adapter."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from python_security_auditing.runners import (
    AuditError,
    generate_requirements,
    read_bandit_sarif,
    run_pip_audit,
)
from python_security_auditing.settings import Settings

FIXTURES = Path(__file__).parent / "fixtures"
CLEAN_REPORT = json.dumps({"dependencies": [], "fixes": []})


# ---------------------------------------------------------------------------
# generate_requirements
# ---------------------------------------------------------------------------


def test_requirements_mode_returns_configured_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "custom-requirements.txt").write_text("requests==2.31.0\n")
    monkeypatch.setenv("PACKAGE_MANAGER", "requirements")
    monkeypatch.setenv("REQUIREMENTS_FILE", "custom-requirements.txt")
    s = Settings()
    assert generate_requirements(s) == Path("custom-requirements.txt")


def test_requirements_mode_raises_when_file_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PACKAGE_MANAGER", "requirements")
    with pytest.raises(AuditError, match="requirements file not found: requirements.txt"):
        generate_requirements(Settings())


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
    # the caller's own project is not on PyPI: emitting it makes pip-audit build it
    assert "--no-emit-project" in cmd
    assert str(result).endswith("-requirements.txt")


def test_pip_mode_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """`pip freeze` would list the action's own environment, so pip mode must fail."""
    monkeypatch.setenv("PACKAGE_MANAGER", "pip")
    with patch("python_security_auditing.runners.subprocess.run") as mock_run:
        with pytest.raises(AuditError, match=r"pip freeze > requirements\.txt"):
            generate_requirements(Settings())
    mock_run.assert_not_called()


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


def test_pipenv_mode_calls_pipenv_requirements(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "Pipfile.lock").write_text("{}")
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


@pytest.mark.parametrize(
    ("returncode", "stdout"),
    [(1, ""), (0, ""), (1, "Traceback (most recent call last):"), (0, "[]"), (2, "{}")],
)
def test_run_pip_audit_raises_without_json_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, returncode: int, stdout: str
) -> None:
    """pip-audit exits 1 for findings AND for fatal errors: only a JSON report counts."""
    monkeypatch.chdir(tmp_path)

    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(
            returncode=returncode, stderr="ERROR:pip_audit._cli:boom", stdout=stdout
        )
        with pytest.raises(AuditError, match=rf"exit {returncode}\):\nERROR:pip_audit\._cli:boom"):
            run_pip_audit(Path("requirements.txt"))

    assert not (tmp_path / "pip-audit-report.json").exists()


def test_run_pip_audit_uses_requirements_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    req_path = tmp_path / "custom-reqs.txt"

    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout=CLEAN_REPORT)
        run_pip_audit(req_path)

    cmd = mock_run.call_args[0][0]
    assert str(req_path) in cmd
    assert "-f" in cmd
    assert "json" in cmd


@pytest.mark.parametrize(
    ("package_manager", "disable_pip"),
    [("uv", True), ("poetry", True), ("pipenv", True), ("requirements", False)],
)
def test_run_pip_audit_disables_pip_for_pinned_exports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, package_manager: str, disable_pip: bool
) -> None:
    """Exports are fully pinned; a requirements file may not be, so pip resolves it."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PACKAGE_MANAGER", package_manager)
    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout=CLEAN_REPORT)
        run_pip_audit(Path("requirements.txt"), Settings())
    cmd = mock_run.call_args[0][0]
    assert "--no-deps" in cmd
    assert ("--disable-pip" in cmd) is disable_pip


# ---------------------------------------------------------------------------
# generate_requirements — export failures must fail, not return an empty file
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("package_manager", ["uv", "poetry", "pipenv"])
def test_generate_requirements_raises_when_export_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, package_manager: str
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "Pipfile.lock").write_text("{}")
    monkeypatch.setenv("PACKAGE_MANAGER", package_manager)
    exc = subprocess.CalledProcessError(2, package_manager, stderr="lockfile is broken")
    # poetry first runs `poetry self add`, which may fail without consequence
    side_effect = [MagicMock(returncode=1), exc] if package_manager == "poetry" else exc
    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run", side_effect=side_effect),
    ):
        with pytest.raises(AuditError, match=f"{package_manager} .*failed: lockfile is broken"):
            generate_requirements(Settings())


def test_generate_requirements_pipenv_raises_without_lockfile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`pipenv requirements` exits 0 with no packages when Pipfile.lock is missing."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PACKAGE_MANAGER", "pipenv")
    with patch("python_security_auditing.runners.subprocess.run") as mock_run:
        with pytest.raises(AuditError, match="Pipfile.lock not found"):
            generate_requirements(Settings())
    mock_run.assert_not_called()


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
