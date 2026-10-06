"""Tests for annotations.py — GitHub Actions workflow command emission."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest
from python_security_auditing.annotations import emit_annotations
from python_security_auditing.settings import Settings

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture()
def bandit_issues() -> dict[str, Any]:
    return cast(dict[str, Any], load("bandit_issues.json"))


@pytest.fixture()
def bandit_clean() -> dict[str, Any]:
    return cast(dict[str, Any], load("bandit_clean.json"))


@pytest.fixture()
def pip_fixable() -> list[Any]:
    return cast(list[Any], load("pip_audit_fixable.json"))


@pytest.fixture()
def pip_clean() -> list[Any]:
    return cast(list[Any], load("pip_audit_clean.json"))


def test_bandit_high_emits_error(
    bandit_issues: dict[str, Any], pip_clean: list[Any], capsys: pytest.CaptureFixture[str]
) -> None:
    s = Settings()
    emit_annotations(bandit_issues, pip_clean, s)
    out = capsys.readouterr().out
    assert "::error file=src/app.py,line=2::[B404]" in out


def test_bandit_medium_emits_warning(
    bandit_issues: dict[str, Any], pip_clean: list[Any], capsys: pytest.CaptureFixture[str]
) -> None:
    s = Settings()
    emit_annotations(bandit_issues, pip_clean, s)
    out = capsys.readouterr().out
    assert "::warning file=src/app.py,line=5::[B602]" in out


def test_bandit_high_before_medium(
    bandit_issues: dict[str, Any], pip_clean: list[Any], capsys: pytest.CaptureFixture[str]
) -> None:
    """HIGH findings must appear before MEDIUM in output."""
    s = Settings()
    emit_annotations(bandit_issues, pip_clean, s)
    out = capsys.readouterr().out
    assert out.index("::error") < out.index("::warning")


def test_bandit_clean_emits_nothing(
    bandit_clean: dict[str, Any], pip_clean: list[Any], capsys: pytest.CaptureFixture[str]
) -> None:
    s = Settings()
    emit_annotations(bandit_clean, pip_clean, s)
    out = capsys.readouterr().out
    assert out == ""


def test_pip_audit_fixable_emits_warning(
    bandit_clean: dict[str, Any], pip_fixable: list[Any], capsys: pytest.CaptureFixture[str]
) -> None:
    s = Settings()
    emit_annotations(bandit_clean, pip_fixable, s)
    out = capsys.readouterr().out
    assert "::warning::pip-audit:" in out
    assert "GHSA-" in out


def test_pip_audit_no_file_line_in_annotation(
    bandit_clean: dict[str, Any], pip_fixable: list[Any], capsys: pytest.CaptureFixture[str]
) -> None:
    """pip-audit annotations must not include file= or line= (no file context)."""
    s = Settings()
    emit_annotations(bandit_clean, pip_fixable, s)
    out = capsys.readouterr().out
    pip_lines = [line for line in out.splitlines() if "pip-audit" in line]
    for line in pip_lines:
        assert "file=" not in line


def test_pip_clean_emits_nothing(
    bandit_clean: dict[str, Any], pip_clean: list[Any], capsys: pytest.CaptureFixture[str]
) -> None:
    s = Settings()
    emit_annotations(bandit_clean, pip_clean, s)
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    "report",
    [[], [{"name": "my-app", "version": "0.1.0", "skip_reason": "Dependency not found on PyPI"}]],
)
def test_pip_zero_audited_emits_warning(
    bandit_clean: dict[str, Any], report: list[Any], capsys: pytest.CaptureFixture[str]
) -> None:
    emit_annotations(bandit_clean, report, Settings())
    assert capsys.readouterr().out.startswith("::warning::pip-audit audited 0 dependencies")


def test_pip_audit_error_emits_escaped_error(
    bandit_clean: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    emit_annotations(bandit_clean, [], Settings(), pip_audit_error="uv failed\n100% broken")
    out = capsys.readouterr().out
    assert out == "::error::pip-audit did NOT run: uv failed%0A100%25 broken\n"


def test_bandit_error_emits_escaped_error(
    pip_clean: list[Any], capsys: pytest.CaptureFixture[str]
) -> None:
    emit_annotations({}, pip_clean, Settings(), bandit_error="bandit failed (exit 2):\nusage")
    out = capsys.readouterr().out
    assert out == "::error::bandit did NOT run: bandit failed (exit 2):%0Ausage\n"


def test_bandit_file_property_is_escaped(
    pip_clean: list[Any], capsys: pytest.CaptureFixture[str]
) -> None:
    """In a property value ':' and ',' are separators, so they must be %-encoded too."""
    result = {"issue_severity": "HIGH", "filename": "a,b:c%.py", "line_number": 3, "test_id": "B1"}
    emit_annotations({"results": [result]}, pip_clean, Settings())
    assert capsys.readouterr().out == "::error file=a%2Cb%3Ac%25.py,line=3::[B1] \n"


def test_bandit_without_file_metrics_warns(
    bandit_clean: dict[str, Any], pip_clean: list[Any], capsys: pytest.CaptureFixture[str]
) -> None:
    emit_annotations({**bandit_clean, "files_read": None}, pip_clean, Settings())
    assert capsys.readouterr().out.startswith("::warning::bandit reported no file metrics")


def test_bandit_only_tool_skips_pip(
    bandit_clean: dict[str, Any],
    pip_fixable: list[Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("TOOLS", "bandit")
    s = Settings()
    emit_annotations(bandit_clean, pip_fixable, s)
    assert capsys.readouterr().out == ""


def test_pip_only_tool_skips_bandit(
    bandit_issues: dict[str, Any],
    pip_clean: list[Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("TOOLS", "pip-audit")
    s = Settings()
    emit_annotations(bandit_issues, pip_clean, s)
    assert capsys.readouterr().out == ""
