"""Tool invocation and package manager adapter."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from .settings import Settings


def generate_requirements(settings: Settings) -> Path:
    """Return a requirements.txt Path suitable for pip-audit.

    For package managers that don't produce a file directly (pip, pipenv),
    captures stdout into a temp file. For 'requirements', returns the
    configured path unchanged.
    """
    pm = settings.package_manager

    if pm == "requirements":
        return Path(settings.requirements_file)

    tmp = tempfile.NamedTemporaryFile(suffix="-requirements.txt", delete=False, mode="w")
    tmp.close()
    out_path = Path(tmp.name)

    if pm == "uv":
        subprocess.run(
            ["uv", "export", "--format", "requirements-txt", "--no-hashes", "-o", str(out_path)],
            check=True,
            capture_output=True,
            text=True,
        )
    elif pm == "pip":
        result = subprocess.run(["pip", "freeze"], capture_output=True, text=True, check=True)
        out_path.write_text(result.stdout)
    elif pm == "poetry":
        subprocess.run(
            [
                "poetry",
                "export",
                "--format",
                "requirements.txt",
                "--without-hashes",
                "-o",
                str(out_path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    elif pm == "pipenv":
        result = subprocess.run(
            ["pipenv", "requirements"], capture_output=True, text=True, check=True
        )
        out_path.write_text(result.stdout)

    return out_path


_SARIF_LEVEL_TO_SEVERITY: dict[str, str] = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "note": "LOW",
    "none": "LOW",
}


def read_bandit_sarif(sarif_path: Path) -> dict[str, Any]:
    """Read results.sarif produced by lhoupert/bandit-action, return bandit-style report dict."""
    if not sarif_path.exists():
        return {"results": [], "errors": []}

    sarif: dict[str, Any] = json.loads(sarif_path.read_text())
    sarif_results: list[dict[str, Any]] = sarif.get("runs", [{}])[0].get("results", [])
    results: list[dict[str, Any]] = []
    for sarif_result in sarif_results:
        props: dict[str, Any] = sarif_result.get("properties", {})
        severity = props.get("issue_severity") or _SARIF_LEVEL_TO_SEVERITY.get(
            sarif_result.get("level", "none"), "LOW"
        )
        locations: list[dict[str, Any]] = sarif_result.get("locations", [])
        filename = ""
        line_number = 0
        if locations:
            phys = locations[0].get("physicalLocation", {})
            filename = phys.get("artifactLocation", {}).get("uri", "")
            line_number = phys.get("region", {}).get("startLine", 0)
        results.append(
            {
                "issue_severity": severity,
                "issue_confidence": props.get("issue_confidence", ""),
                "issue_text": sarif_result.get("message", {}).get("text", ""),
                "filename": filename,
                "line_number": line_number,
                "test_id": sarif_result.get("ruleId", ""),
            }
        )

    return {"results": results, "errors": []}


def run_pip_audit(requirements_path: Path) -> list[dict[str, Any]]:
    """Run pip-audit, write pip-audit-report.json, return parsed report."""
    output_file = Path("pip-audit-report.json")
    cmd = ["pip-audit", "-r", str(requirements_path), "-f", "json"]

    result = subprocess.run(cmd, capture_output=True, text=True)
    # pip-audit exits 1 when vulnerabilities are found — that is expected
    if result.returncode not in (0, 1):
        print(
            f"pip-audit exited with unexpected code {result.returncode}:\n{result.stderr}",
            file=sys.stderr,
        )

    raw = result.stdout.strip()
    if raw:
        parsed: Any = json.loads(raw)
        output_file.write_text(raw)
        # pip-audit 2.7+ wraps output in {"dependencies": [...], "fixes": [...]}
        if isinstance(parsed, dict):
            return parsed.get("dependencies", [])
        return parsed
    return []
