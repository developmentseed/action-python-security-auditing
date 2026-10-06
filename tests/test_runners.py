"""Tests for runners.py — tool invocation and package manager adapter."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from python_security_auditing.runners import (
    AuditError,
    generate_requirements,
    read_bandit_sarif,
    run_bandit,
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


def _bandit_sarif(
    results: tuple[dict[str, Any], ...] = (),
    files: tuple[str, ...] = ("./app.py",),
    skipped: tuple[tuple[str, str], ...] = (),
) -> str:
    """A SARIF report shaped like bandit's: metrics per file read, skipped files as notices."""
    notices = [
        {
            "level": "error",
            "message": {"text": reason},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
        }
        for uri, reason in skipped
    ]
    run = {
        "results": list(results),
        "invocations": [{"executionSuccessful": True, "toolConfigurationNotifications": notices}],
        "properties": {"metrics": {name: {"loc": 1} for name in ("_totals", *files)}},
    }
    return json.dumps({"version": "2.1.0", "runs": [run]})


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


def test_read_bandit_sarif_decodes_paths(tmp_path: Path) -> None:
    """bandit %-encodes SARIF URIs; annotations and the report need the real path."""
    sarif_path = tmp_path / "results.sarif"
    location = {"physicalLocation": {"artifactLocation": {"uri": "src/my%20app.py"}}}
    sarif_path.write_text(_bandit_sarif(results=({"ruleId": "B602", "locations": [location]},)))
    assert read_bandit_sarif(sarif_path)["results"][0]["filename"] == "src/my app.py"


@pytest.mark.parametrize("content", [None, "", "not json", "[]", '{"runs": []}'])
def test_read_bandit_sarif_raises_on_missing_or_invalid_file(
    tmp_path: Path, content: str | None
) -> None:
    sarif_path = tmp_path / "results.sarif"
    if content is not None:
        sarif_path.write_text(content)
    with pytest.raises(AuditError, match="bandit wrote no valid SARIF report"):
        read_bandit_sarif(sarif_path)


def test_read_bandit_sarif_returns_empty_on_clean_sarif(tmp_path: Path) -> None:
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text((FIXTURES / "bandit_clean.sarif").read_text())
    report = read_bandit_sarif(sarif_path)
    assert report == {"results": [], "errors": [], "files_read": 1}


def test_read_bandit_sarif_falls_back_to_level_mapping(tmp_path: Path) -> None:
    sarif_path = tmp_path / "results.sarif"
    result = {"ruleId": "B999", "level": "warning", "message": {"text": "test issue"}}
    sarif_path.write_text(_bandit_sarif(results=(result,)))
    report = read_bandit_sarif(sarif_path)
    assert report["results"][0]["issue_severity"] == "MEDIUM"


def test_read_bandit_sarif_lists_skipped_files(tmp_path: Path) -> None:
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text(
        _bandit_sarif(
            files=("./src/app.py", "./src/new syntax.py"),
            skipped=(("src/new%20syntax.py", "syntax error while parsing AST from file"),),
        )
    )
    report = read_bandit_sarif(sarif_path)
    assert report["errors"] == [
        {"filename": "src/new syntax.py", "reason": "syntax error while parsing AST from file"}
    ]
    assert report["files_read"] == 2


def test_read_bandit_sarif_tolerates_missing_bandit_details(tmp_path: Path) -> None:
    """Metrics and invocations are bandit details a release may drop: not a failure."""
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text(json.dumps({"runs": [{"results": [{"ruleId": "B602"}]}]}))
    report = read_bandit_sarif(sarif_path)
    assert [r["test_id"] for r in report["results"]] == ["B602"]
    assert report["errors"] == []
    assert report["files_read"] is None  # unknown


@pytest.mark.parametrize(
    "run",
    [
        {"results": None},
        {"results": [1]},
        {"results": [{"locations": [{"physicalLocation": {"artifactLocation": {"uri": 5}}}]}]},
        {"results": [], "properties": {"metrics": 5}},
    ],
)
def test_read_bandit_sarif_raises_on_malformed_values(tmp_path: Path, run: dict[str, Any]) -> None:
    """A malformed report must not crash the run before pip-audit, nor reach Code Scanning."""
    sarif_path = tmp_path / "results.sarif"
    sarif_path.write_text(json.dumps({"runs": [run]}))
    with pytest.raises(AuditError, match="bandit wrote no valid SARIF report"):
        read_bandit_sarif(sarif_path)


# ---------------------------------------------------------------------------
# run_bandit
# ---------------------------------------------------------------------------


def _fake_bandit(sarif: str | None, returncode: int = 0, stderr: str = "") -> Any:
    """subprocess.run stand-in: bandit writes `sarif` (if any) to its -o path."""

    def run(cmd: list[str], **kwargs: object) -> MagicMock:
        if sarif is not None:
            Path(cmd[cmd.index("-o") + 1]).write_text(sarif)
        return MagicMock(returncode=returncode, stderr=stderr, stdout="")

    return run


def test_run_bandit_builds_command_from_workspace_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Comma-separated dirs become separate targets, relative to the repository root."""
    (tmp_path / "proj/src").mkdir(parents=True)
    (tmp_path / "proj/scripts").mkdir()
    monkeypatch.chdir(tmp_path / "proj")  # working_directory
    sarif_path = tmp_path / "results.sarif"
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    monkeypatch.setenv("BANDIT_SCAN_DIRS", "src/, scripts")
    monkeypatch.setenv("BANDIT_SARIF_PATH", str(sarif_path))

    with patch(
        "python_security_auditing.runners.subprocess.run",
        side_effect=_fake_bandit(_bandit_sarif()),
    ) as mock_run:
        run_bandit(Settings())

    # the bandit of the action's own environment, never one found on PATH
    assert mock_run.call_args[0][0] == [
        sys.executable,
        "-m",
        "bandit",
        "-r",
        "proj/src",
        "proj/scripts",
        "-f",
        "sarif",
        "-o",
        str(sarif_path.resolve()),
        "--exit-zero",
    ]
    assert mock_run.call_args.kwargs["cwd"] == tmp_path.resolve()


@pytest.mark.parametrize(
    ("dirs", "targets"),
    [
        ("src, ., ./src/, scripts", ["."]),
        ("src/sub, src, scripts, src/", ["src", "scripts"]),
    ],
)
def test_run_bandit_scans_overlapping_dirs_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, dirs: str, targets: list[str]
) -> None:
    """bandit would report the files of overlapping dirs twice, under different paths."""
    (tmp_path / "src/sub").mkdir(parents=True)
    (tmp_path / "scripts").mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("BANDIT_SCAN_DIRS", dirs)
    with patch(
        "python_security_auditing.runners.subprocess.run",
        side_effect=_fake_bandit(_bandit_sarif()),
    ) as mock_run:
        run_bandit(Settings())
    cmd = mock_run.call_args[0][0]
    assert cmd[4 : cmd.index("-f")] == targets


def test_run_bandit_defaults_to_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    with patch(
        "python_security_auditing.runners.subprocess.run",
        side_effect=_fake_bandit(_bandit_sarif()),
    ) as mock_run:
        run_bandit(Settings())
    assert mock_run.call_args[0][0][3:5] == ["-r", "."]
    assert mock_run.call_args.kwargs["cwd"] == tmp_path.resolve()


@pytest.mark.parametrize(
    "sarif",
    [
        (FIXTURES / "bandit_issues.sarif").read_text(),
        # no metrics: the file count is unknown, so the exit code and the SARIF decide
        json.dumps({"runs": [{"results": [{"ruleId": "B404"}, {"ruleId": "B602"}]}]}),
    ],
)
def test_run_bandit_returns_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sarif: str
) -> None:
    """With --exit-zero, bandit exits 0 when it finds issues; the SARIF is kept for upload."""
    monkeypatch.chdir(tmp_path)
    with patch("python_security_auditing.runners.subprocess.run", side_effect=_fake_bandit(sarif)):
        report = run_bandit(Settings())
    assert [r["test_id"] for r in report["results"]] == ["B404", "B602"]
    assert (tmp_path / "results.sarif").read_text() == sarif


def test_run_bandit_keeps_findings_when_files_are_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The findings of the other files are reported; the partial SARIF is not uploaded."""
    monkeypatch.chdir(tmp_path)
    issues = json.loads((FIXTURES / "bandit_issues.sarif").read_text())["runs"][0]["results"]
    sarif = _bandit_sarif(
        results=tuple(issues),
        files=("./src/app.py", "./new.py"),
        skipped=(("new.py", "syntax error while parsing AST from file"),),
    )
    with patch("python_security_auditing.runners.subprocess.run", side_effect=_fake_bandit(sarif)):
        report = run_bandit(Settings())
    assert [r["test_id"] for r in report["results"]] == ["B404", "B602"]
    assert report["errors"] == [
        {"filename": "new.py", "reason": "syntax error while parsing AST from file"}
    ]
    # a partial report would close the skipped file's Code Scanning alerts
    assert not (tmp_path / "results.sarif").exists()


@pytest.mark.parametrize(
    ("sarif", "returncode", "stderr", "message"),
    [
        # usage error: argparse has already created an empty -o file
        ("", 2, "bandit: error: unrecognized arguments", r"exit 2\):\nbandit: error: unrec"),
        # crash: an uncaught exception exits 1 and writes no report
        (None, 1, "Traceback (most recent call last):", r"exit 1\):\nTraceback"),
        (None, 0, "", "bandit wrote no valid SARIF report"),
        ("not json", 0, "", "bandit wrote no valid SARIF report"),
        ('{"runs": [{"results": null}]}', 0, "", "bandit wrote no valid SARIF report"),
        (_bandit_sarif(files=()), 0, "", r"no Python file to scan in \['.'\]"),
    ],
)
def test_run_bandit_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    sarif: str | None,
    returncode: int,
    stderr: str,
    message: str,
) -> None:
    """A failed or empty scan raises, and leaves no SARIF to upload."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "results.sarif").write_text(_bandit_sarif())  # an earlier run's report
    with patch(
        "python_security_auditing.runners.subprocess.run",
        side_effect=_fake_bandit(sarif, returncode, stderr),
    ):
        with pytest.raises(AuditError, match=message):
            run_bandit(Settings())
    assert not (tmp_path / "results.sarif").exists()


def test_run_bandit_truncates_long_stderr(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """stderr ends up in the PR comment, which GitHub caps at 65,536 characters."""
    monkeypatch.chdir(tmp_path)
    stderr = "x" * 10_000 + "\nValueError: the real cause"
    with patch(
        "python_security_auditing.runners.subprocess.run",
        side_effect=_fake_bandit(None, 1, stderr),
    ):
        with pytest.raises(AuditError) as exc_info:
            run_bandit(Settings())
    message = str(exc_info.value)
    assert len(message) < 2_100
    assert "… (truncated)" in message
    assert message.endswith("ValueError: the real cause")


def test_run_bandit_rejects_missing_scan_dirs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A misspelt dir next to a valid one would otherwise go unscanned with a warning."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "results.sarif").write_text(_bandit_sarif())  # an earlier run's report
    monkeypatch.setenv("BANDIT_SCAN_DIRS", "src, scirpts,gone/")
    with patch("python_security_auditing.runners.subprocess.run") as mock_run:
        with pytest.raises(AuditError, match="bandit_scan_dirs not found in .*: scirpts, gone/"):
            run_bandit(Settings())
    mock_run.assert_not_called()
    assert not (tmp_path / "results.sarif").exists()


def test_run_bandit_wraps_os_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An OSError must not crash the run before pip-audit and the summary."""
    monkeypatch.chdir(tmp_path)
    with patch(
        "python_security_auditing.runners.subprocess.run",
        side_effect=PermissionError(13, "Permission denied"),
    ):
        with pytest.raises(AuditError, match="bandit could not run: .*Permission denied"):
            run_bandit(Settings())


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
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(tmpdir))
    exc = subprocess.CalledProcessError(2, package_manager, stderr="lockfile is broken")
    # poetry first runs `poetry self add`, which may fail without consequence
    side_effect = [MagicMock(returncode=1), exc] if package_manager == "poetry" else exc
    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run", side_effect=side_effect),
    ):
        with pytest.raises(AuditError, match=f"{package_manager} .*failed: lockfile is broken"):
            generate_requirements(Settings())
    assert list(tmpdir.iterdir()) == []  # no leaked temp requirements file


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


def test_generate_requirements_pipenv_uses_lockfile_next_to_pipenv_pipfile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """pipenv keeps the lock at <PIPENV_PIPFILE>.lock, not in the current directory."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "Pipfile.lock").write_text("{}")
    monkeypatch.setenv("PIPENV_PIPFILE", str(tmp_path / "sub" / "Pipfile"))
    monkeypatch.setenv("PACKAGE_MANAGER", "pipenv")
    with (
        patch("python_security_auditing.runners.shutil.which", side_effect=lambda exe: exe),
        patch("python_security_auditing.runners.subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=0, stdout="requests==2.31.0\n")
        result = generate_requirements(Settings())
    assert result.read_text() == "requests==2.31.0\n"


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
