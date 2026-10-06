"""Tool invocation and package manager adapter."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from .settings import Settings

PIP_AUDIT_REPORT = Path("pip-audit-report.json")


class AuditError(Exception):
    """A tool could not run, so its report could not be produced."""


def _resolve_exe(name: str) -> str:
    """Resolve an executable name to its full path via PATH, raising if not found."""
    resolved = shutil.which(name)
    if resolved is None:
        raise FileNotFoundError(f"Required tool not found on PATH: {name!r}")
    return resolved


def generate_requirements(settings: Settings) -> Path:
    """Return a requirements.txt Path suitable for pip-audit.

    For package managers that don't produce a file directly (pipenv),
    captures stdout into a temp file. For 'requirements', returns the
    configured path unchanged. Raises AuditError when no list can be produced.
    """
    pm = settings.package_manager

    if pm == "pip":
        # `pip freeze` here would list this action's own environment, not the caller's.
        raise AuditError(
            "package_manager 'pip' is not supported: run `pip freeze > requirements.txt` "
            "in your job and use `package_manager: requirements`."
        )

    if pm == "requirements":
        path = Path(settings.requirements_file)
        if not path.is_file():
            raise AuditError(f"requirements file not found: {path}")
        return path

    if pm == "pipenv":
        # pipenv keeps the lock at <Pipfile>.lock. Without it, `pipenv requirements`
        # exits 0 and prints no packages.
        lock = Path(os.environ.get("PIPENV_PIPFILE", "Pipfile") + ".lock")
        if not lock.is_file():
            raise AuditError(f"{lock} not found: commit it or run `pipenv lock` first.")

    # Check everything that can fail before creating the temp file, so it is not leaked.
    exe = _resolve_exe(pm)
    tmp = tempfile.NamedTemporaryFile(suffix="-requirements.txt", delete=False, mode="w")
    tmp.close()
    out_path = Path(tmp.name)

    if pm == "uv":
        cmd = [
            exe,
            "export",
            "--format",
            "requirements-txt",
            "--no-hashes",
            "--no-emit-project",
            "-o",
            str(out_path),
        ]
        if settings.debug:
            print(f"[debug] uv export command: {cmd}", file=sys.stderr)
        try:
            subprocess.run(  # nosec B603,B605 -- list args, full path via _resolve_exe()
                cmd,
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            out_path.unlink()
            raise AuditError(f"uv export failed: {exc.stderr.strip()}") from exc
        if settings.debug:
            print(
                f"[debug] generated requirements ({out_path}):\n{out_path.read_text()}",
                file=sys.stderr,
            )
    elif pm == "poetry":
        # poetry-plugin-export is bundled in Poetry 1.8+; ignore failure here
        subprocess.run(  # nosec B603,B605 -- list args, full path via _resolve_exe()
            [exe, "self", "add", "poetry-plugin-export"],
            check=False,
            capture_output=True,
            text=True,
        )
        try:
            subprocess.run(  # nosec B603,B605 -- list args, full path via _resolve_exe()
                [
                    exe,
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
        except subprocess.CalledProcessError as exc:
            out_path.unlink()
            raise AuditError(f"poetry export failed: {exc.stderr.strip()}") from exc
        if settings.debug:
            print(
                f"[debug] poetry export output ({out_path}):\n{out_path.read_text()}",
                file=sys.stderr,
            )
    elif pm == "pipenv":
        try:
            result = subprocess.run(  # nosec B603,B605 -- list args, full path via _resolve_exe()
                [exe, "requirements"], capture_output=True, text=True, check=True
            )
            out_path.write_text(result.stdout)
        except subprocess.CalledProcessError as exc:
            out_path.unlink()
            raise AuditError(f"pipenv requirements failed: {exc.stderr.strip()}") from exc
        if settings.debug:
            print(
                f"[debug] pipenv requirements output ({out_path}):\n{result.stdout}",
                file=sys.stderr,
            )

    return out_path


_SARIF_LEVEL_TO_SEVERITY: dict[str, str] = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "note": "LOW",
    "none": "LOW",
}


def read_bandit_sarif(sarif_path: Path) -> dict[str, Any]:
    """Read bandit's SARIF report, return a bandit-style report dict.

    "errors" lists the files bandit skipped. "files_read" counts the files bandit read, or is
    None when the report has no per-file metrics. Raises AuditError when the report is
    missing or is not SARIF.
    """
    try:
        run: dict[str, Any] = json.loads(sarif_path.read_text())["runs"][0]
        # bandit details, which a release could drop: it lists the files it could not open or
        # parse as notifications, and keeps metrics for every file it read, plus "_totals".
        errors = []
        for notice in (run.get("invocations") or [{}])[0].get("toolConfigurationNotifications", []):
            phys = (notice.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = phys.get("artifactLocation", {}).get("uri", "")
            errors.append({"filename": unquote(uri), "reason": notice["message"]["text"]})
        metrics = run.get("properties", {}).get("metrics")
    except (OSError, ValueError, LookupError, TypeError, AttributeError) as exc:
        raise AuditError(f"bandit wrote no valid SARIF report to {sarif_path}: {exc!r}") from exc

    results: list[dict[str, Any]] = []
    for sarif_result in run.get("results", []):
        props: dict[str, Any] = sarif_result.get("properties", {})
        severity = props.get("issue_severity") or _SARIF_LEVEL_TO_SEVERITY.get(
            sarif_result.get("level", "none"), "LOW"
        )
        locations: list[dict[str, Any]] = sarif_result.get("locations", [])
        filename = ""
        line_number = 0
        if locations:
            phys = locations[0].get("physicalLocation", {})
            filename = unquote(phys.get("artifactLocation", {}).get("uri", ""))  # bandit %-encodes
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

    files_read = None if metrics is None else len(set(metrics) - {"_totals"})
    return {"results": results, "errors": errors, "files_read": files_read}


def run_bandit(settings: Settings) -> dict[str, Any]:
    """Run bandit on bandit_scan_dirs, write its SARIF report, return the parsed report.

    Raises AuditError, and leaves no SARIF report, when bandit cannot run, fails, skips a
    file or reads none: an empty or partial report would close open Code Scanning alerts.
    """
    sarif_path = Path(settings.bandit_sarif_path).resolve()
    try:
        sarif_path.unlink(missing_ok=True)  # never upload an earlier run's report
        dirs = [d.strip() for d in settings.bandit_scan_dirs.split(",") if d.strip()]
        missing = [d for d in dirs if not Path(d).exists()]
        if missing:
            raise AuditError(f"bandit_scan_dirs not found in {Path.cwd()}: {', '.join(missing)}")
        # Run from the repository root, so that SARIF paths (annotations, Code Scanning)
        # stay relative to it whatever the working directory.
        root = Path(settings.github_workspace or ".").resolve()
        targets = [os.path.relpath(Path(d).resolve(), root) for d in dirs]
        # With --exit-zero findings exit 0 too, so any other exit is a crash or a usage error.
        cmd = [_resolve_exe("bandit"), "-r", *targets, "-f", "sarif", "-o", str(sarif_path)]
        cmd += ["--exit-zero"]

        if settings.debug:
            print(f"[debug] bandit command (cwd={root}): {cmd}", file=sys.stderr)

        result = subprocess.run(cmd, cwd=root, capture_output=True, text=True)  # nosec B603 -- list args, full path via _resolve_exe()

        if settings.debug:
            print(
                f"[debug] bandit exit={result.returncode} stderr={result.stderr!r}", file=sys.stderr
            )

        if result.returncode:
            raise AuditError(f"bandit failed (exit {result.returncode}):\n{result.stderr.strip()}")
        report = read_bandit_sarif(sarif_path)
        if skipped := [f"{e['filename']}: {e['reason']}" for e in report["errors"]]:
            count = len(skipped)
            if count > 20:  # the list ends up in the PR comment, which GitHub caps at 65,536 chars
                skipped[20:] = [f"… and {count - 20} more"]
            raise AuditError(
                f"bandit could not scan {count} file(s), so they were NOT checked:\n"
                + "\n".join(skipped)
                + "\nFix them, or skip them on purpose: list them under `exclude` in the [bandit] "
                "section of a `.bandit` file in a scanned directory."
            )
        if report["files_read"] == 0:
            raise AuditError(f"bandit found no Python file to scan in {targets}")
    except (AuditError, OSError) as exc:
        with contextlib.suppress(OSError):
            sarif_path.unlink(missing_ok=True)
        if isinstance(exc, AuditError):
            raise
        raise AuditError(f"bandit could not run: {exc}") from exc
    return report


def run_pip_audit(
    requirements_path: Path, settings: Settings | None = None
) -> list[dict[str, Any]]:
    """Run pip-audit, write pip-audit-report.json, return parsed report.

    Raises AuditError when pip-audit does not produce a JSON report.
    """
    cmd = [_resolve_exe("pip-audit"), "-r", str(requirements_path), "--no-deps", "-f", "json"]
    if settings and settings.package_manager != "requirements":
        # Exports are fully pinned: audit them as written. Without --disable-pip,
        # pip-audit resolves them with pip (building the project) and ignores --no-deps.
        cmd.append("--disable-pip")

    if settings and settings.debug:
        print(f"[debug] pip-audit command: {cmd}", file=sys.stderr)

    result = subprocess.run(cmd, capture_output=True, text=True)  # nosec B603,B605 -- list args, full path via _resolve_exe()

    if settings and settings.debug:
        print(
            f"[debug] pip-audit exit={result.returncode} "
            f"stdout_len={len(result.stdout)} stderr={result.stderr!r}",
            file=sys.stderr,
        )

    # pip-audit exits 1 both when it finds vulnerabilities and when it fails,
    # so only a JSON report proves that the audit ran.
    try:
        dependencies = list(json.loads(result.stdout)["dependencies"])
    except (ValueError, KeyError, TypeError) as exc:
        raise AuditError(
            f"pip-audit failed (exit {result.returncode}):\n{result.stderr.strip()}"
        ) from exc
    PIP_AUDIT_REPORT.write_text(result.stdout)
    return dependencies
