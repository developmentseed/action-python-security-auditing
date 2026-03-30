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
