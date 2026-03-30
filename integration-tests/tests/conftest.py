"""Shared pytest fixtures for validate_results tests."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest


def _sarif_doc(results: list[dict[str, Any]]) -> dict[str, Any]:
    return {"version": "2.1.0", "runs": [{"results": results}]}


@pytest.fixture()
def sample_sarif() -> dict[str, Any]:
    """Minimal SARIF document with two findings."""
    return _sarif_doc(
        [
            {"ruleId": "B602", "level": "error"},
            {"ruleId": "B105", "level": "warning"},
        ]
    )


@pytest.fixture()
def sample_pip_audit_report() -> dict[str, Any]:
    """Minimal pip-audit JSON report with one fixable vulnerability."""
    return {
        "dependencies": [
            {
                "name": "requests",
                "version": "2.25.0",
                "vulns": [
                    {
                        "id": "GHSA-test-xxxx-xxxx",
                        "fix_versions": ["2.32.0"],
                    }
                ],
            }
        ]
    }


@pytest.fixture()
def make_artifact_dir(
    tmp_path: Path,
) -> Callable[[str, dict[str, Any] | None, dict[str, Any] | None], Path]:
    """Factory fixture: create an artifact directory with SARIF and/or pip-audit files."""

    def _make(
        num: str,
        sarif: dict[str, Any] | None = None,
        pip_audit: dict[str, Any] | None = None,
    ) -> Path:
        artifact_dir = tmp_path / "artifacts" / f"security-audit-{num}"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        if sarif is not None:
            (artifact_dir / "results.sarif").write_text(json.dumps(sarif))
        if pip_audit is not None:
            (artifact_dir / "pip-audit-report.json").write_text(json.dumps(pip_audit))
        return artifact_dir

    return _make
