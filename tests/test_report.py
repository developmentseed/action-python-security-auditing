"""Tests for report.py — markdown output and threshold logic."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from python_security_auditing.report import (
    bandit_skipped_message,
    build_markdown,
    check_thresholds,
    write_step_summary,
)
from python_security_auditing.settings import Settings

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture()
def bandit_clean() -> dict[str, Any]:
    return cast(dict[str, Any], load("bandit_clean.json"))


@pytest.fixture()
def bandit_issues() -> dict[str, Any]:
    return cast(dict[str, Any], load("bandit_issues.json"))


@pytest.fixture()
def pip_clean() -> list[Any]:
    return cast(list[Any], load("pip_audit_clean.json"))


@pytest.fixture()
def pip_fixable() -> list[Any]:
    return cast(list[Any], load("pip_audit_fixable.json"))


@pytest.fixture()
def pip_unfixable() -> list[Any]:
    return cast(list[Any], load("pip_audit_unfixable.json"))


# ---------------------------------------------------------------------------
# check_thresholds
# ---------------------------------------------------------------------------


def test_clean_no_blocking(bandit_clean: dict[str, Any], pip_clean: list[Any]) -> None:
    s = Settings()
    assert check_thresholds(bandit_clean, pip_clean, s) is False


def test_bandit_high_blocks(bandit_issues: dict[str, Any], pip_clean: list[Any]) -> None:
    s = Settings()  # threshold=HIGH
    assert check_thresholds(bandit_issues, pip_clean, s) is True


def test_bandit_medium_does_not_block_at_high_threshold(
    bandit_issues: dict[str, Any], pip_clean: list[Any]
) -> None:
    """bandit_issues has HIGH and MEDIUM; only HIGH should block when threshold=HIGH."""
    s = Settings()
    # Remove HIGH results so only MEDIUM remain
    medium_only = {
        **bandit_issues,
        "results": [r for r in bandit_issues["results"] if r["issue_severity"] == "MEDIUM"],
    }
    assert check_thresholds(medium_only, pip_clean, s) is False


def test_bandit_medium_blocks_at_medium_threshold(
    bandit_issues: dict[str, Any], pip_clean: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BANDIT_SEVERITY_THRESHOLD", "medium")
    s = Settings()
    medium_only = {
        **bandit_issues,
        "results": [r for r in bandit_issues["results"] if r["issue_severity"] == "MEDIUM"],
    }
    assert check_thresholds(medium_only, pip_clean, s) is True


def test_pip_fixable_blocks_by_default(
    bandit_clean: dict[str, Any], pip_fixable: list[Any]
) -> None:
    s = Settings()  # pip_audit_block_on=fixable
    assert check_thresholds(bandit_clean, pip_fixable, s) is True


def test_pip_unfixable_does_not_block_on_fixable(
    bandit_clean: dict[str, Any], pip_unfixable: list[Any]
) -> None:
    s = Settings()  # pip_audit_block_on=fixable
    assert check_thresholds(bandit_clean, pip_unfixable, s) is False


def test_pip_unfixable_blocks_on_all(
    bandit_clean: dict[str, Any], pip_unfixable: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PIP_AUDIT_BLOCK_ON", "all")
    s = Settings()
    assert check_thresholds(bandit_clean, pip_unfixable, s) is True


def test_pip_fixable_does_not_block_on_none(
    bandit_clean: dict[str, Any], pip_fixable: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PIP_AUDIT_BLOCK_ON", "none")
    s = Settings()
    assert check_thresholds(bandit_clean, pip_fixable, s) is False


def test_bandit_only_tool_skips_pip(
    bandit_issues: dict[str, Any], pip_fixable: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TOOLS", "bandit")
    s = Settings()
    # pip-audit not in enabled tools, so fixable vulns should not block
    result = check_thresholds(bandit_issues, pip_fixable, s)
    # bandit has HIGH which still blocks
    assert result is True


def test_pip_only_tool_skips_bandit(
    bandit_issues: dict[str, Any], pip_fixable: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TOOLS", "pip-audit")
    s = Settings()
    # bandit not in enabled tools, bandit HIGH issues should not block
    result = check_thresholds(bandit_issues, pip_fixable, s)
    assert result is True  # pip-audit fixable issues do block


def test_pip_only_no_bandit_blocking(
    bandit_issues: dict[str, Any], pip_clean: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TOOLS", "pip-audit")
    s = Settings()
    assert check_thresholds(bandit_issues, pip_clean, s) is False


# ---------------------------------------------------------------------------
# build_markdown
# ---------------------------------------------------------------------------


def test_markdown_contains_header(bandit_clean: dict[str, Any], pip_clean: list[Any]) -> None:
    s = Settings()
    md = build_markdown(bandit_clean, pip_clean, s)
    assert "# Security Audit Report" in md


def test_markdown_clean_result(bandit_clean: dict[str, Any], pip_clean: list[Any]) -> None:
    s = Settings()
    md = build_markdown(bandit_clean, pip_clean, s)
    assert "No blocking issues found" in md
    assert "✅" in md


def test_markdown_blocking_result(bandit_issues: dict[str, Any], pip_clean: list[Any]) -> None:
    s = Settings()
    md = build_markdown(bandit_issues, pip_clean, s)
    assert "Blocking issues found" in md
    assert "❌" in md


def test_markdown_bandit_table(bandit_issues: dict[str, Any], pip_clean: list[Any]) -> None:
    s = Settings()
    md = build_markdown(bandit_issues, pip_clean, s)
    assert "B404" in md
    assert "src/app.py" in md


def test_markdown_below_threshold_summary(
    bandit_issues: dict[str, Any], pip_clean: list[Any]
) -> None:
    """With threshold=HIGH, MEDIUM findings appear as below-threshold note."""
    s = Settings()
    md = build_markdown(bandit_issues, pip_clean, s)
    assert "1 medium issue(s) below threshold not shown in table." in md


def test_markdown_pip_table(bandit_clean: dict[str, Any], pip_fixable: list[Any]) -> None:
    s = Settings()
    md = build_markdown(bandit_clean, pip_fixable, s)
    assert "requests" in md
    assert "GHSA-j8r2-6x86-q33q" in md


def test_markdown_pip_counts_audited_and_skipped(bandit_clean: dict[str, Any]) -> None:
    report: list[dict[str, Any]] = [
        {"name": "requests", "version": "2.32.0", "vulns": []},
        {"name": "my-app", "version": "0.1.0", "skip_reason": "Dependency not found on PyPI"},
    ]
    md = build_markdown(bandit_clean, report, Settings())
    assert "Dependencies audited: 1, skipped: 1" in md
    assert "No vulnerabilities found" in md


@pytest.mark.parametrize(
    "report",
    [[], [{"name": "my-app", "version": "0.1.0", "skip_reason": "Dependency not found on PyPI"}]],
)
def test_markdown_zero_audited_is_not_reported_clean(
    bandit_clean: dict[str, Any], report: list[Any]
) -> None:
    md = build_markdown(bandit_clean, report, Settings())
    assert "No vulnerabilities found" not in md
    assert "No dependencies were audited" in md


def test_markdown_pip_audit_error(bandit_issues: dict[str, Any]) -> None:
    md = build_markdown(bandit_issues, [], Settings(), pip_audit_error="uv export failed: boom")
    assert "B404" in md  # bandit results are still shown
    assert "pip-audit did NOT run" in md
    assert "uv export failed: boom" in md
    assert "No vulnerabilities found" not in md


def test_markdown_bandit_error(pip_fixable: list[Any]) -> None:
    md = build_markdown({}, pip_fixable, Settings(), bandit_error="bandit failed (exit 2)")
    assert "bandit did NOT run" in md
    assert "bandit failed (exit 2)" in md
    assert "No issues found" not in md
    assert "requests" in md  # pip-audit results are still shown
    assert "Blocking issues found" in md


SKIPPED = [{"filename": "src/new.py", "reason": "syntax error while parsing AST from file"}]


def test_markdown_bandit_skipped_files_keep_findings_and_block(
    bandit_issues: dict[str, Any], pip_clean: list[Any]
) -> None:
    md = build_markdown({**bandit_issues, "errors": SKIPPED}, pip_clean, Settings())
    assert "bandit could not scan 1 file(s)" in md
    assert "NOT uploaded to Code Scanning" in md
    assert "src/new.py: syntax error while parsing AST from file" in md
    assert "B404" in md  # the other files' findings are still reported
    assert "Blocking issues found" in md


def test_bandit_skipped_files_block_below_threshold(
    bandit_clean: dict[str, Any], pip_clean: list[Any]
) -> None:
    assert check_thresholds({**bandit_clean, "errors": SKIPPED}, pip_clean, Settings()) is True


def test_bandit_skipped_message_is_capped_and_points_at_a_venv() -> None:
    skipped = [{"filename": f".venv/lib/f{i}.py", "reason": "syntax error"} for i in range(25)]
    message = bandit_skipped_message(skipped)
    assert "could not scan 25 file(s)" in message
    assert ".venv/lib/f19.py: syntax error" in message
    assert ".venv/lib/f20.py" not in message
    assert "… and 5 more" in message
    assert "virtual environment" in message
    # bandit's own default excludes are replaced by an `exclude` list, so it repeats them
    assert "exclude = */.git/*,*/__pycache__/*,*/.tox/*,*/.eggs/*,*.egg,*/.venv/*," in message


def test_bandit_skipped_message_without_venv_has_no_venv_hint() -> None:
    assert "virtual environment" not in bandit_skipped_message(SKIPPED)


def test_markdown_bandit_unknown_file_count(
    bandit_clean: dict[str, Any], pip_clean: list[Any]
) -> None:
    md = build_markdown({**bandit_clean, "files_read": None}, pip_clean, Settings())
    assert "⚠️ Number of files scanned unknown" in md


def test_markdown_run_url(
    bandit_clean: dict[str, Any], pip_clean: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/repo")
    monkeypatch.setenv("GITHUB_RUN_ID", "999")
    s = Settings()
    md = build_markdown(bandit_clean, pip_clean, s)
    assert "github.com/org/repo/actions/runs/999" in md


# ---------------------------------------------------------------------------
# write_step_summary
# ---------------------------------------------------------------------------


def test_write_step_summary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    summary_file = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))
    s = Settings()
    write_step_summary("hello summary", s)
    assert "hello summary" in summary_file.read_text()


def test_write_step_summary_no_path() -> None:
    s = Settings()  # github_step_summary=""
    write_step_summary("ignored", s)  # should not raise
