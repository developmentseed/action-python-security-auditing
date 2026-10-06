"""Orchestrator: load settings → run tools → report → comment → exit."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from .annotations import emit_annotations
from .pr_comment import upsert_pr_comment
from .report import build_markdown, check_thresholds, write_step_summary
from .runners import (
    PIP_AUDIT_REPORT,
    AuditError,
    generate_requirements,
    read_bandit_sarif,
    run_pip_audit,
)
from .settings import Settings


def main() -> None:
    settings = Settings()

    if settings.debug:
        print(f"[debug] settings: {settings.model_dump(exclude={'github_token'})}", file=sys.stderr)

    bandit_report: dict[str, Any] = {}
    pip_audit_report: list[dict[str, Any]] = []
    pip_audit_error = ""

    if "bandit" in settings.enabled_tools:
        if settings.debug:
            print(
                f"[debug] reading bandit SARIF from {settings.bandit_sarif_path}", file=sys.stderr
            )
        bandit_report = read_bandit_sarif(Path(settings.bandit_sarif_path))
        if settings.debug:
            print(
                f"[debug] bandit findings: {len(bandit_report.get('results', []))}", file=sys.stderr
            )

    if "pip-audit" in settings.enabled_tools:
        if settings.debug:
            print(
                f"[debug] generating requirements for package_manager={settings.package_manager}",
                file=sys.stderr,
            )
        PIP_AUDIT_REPORT.unlink(missing_ok=True)  # never upload an earlier run's report
        try:
            requirements_path = generate_requirements(settings)
            if settings.debug:
                print(f"[debug] running pip-audit on {requirements_path}", file=sys.stderr)
            pip_audit_report = run_pip_audit(requirements_path, settings)
        except (AuditError, FileNotFoundError) as exc:
            pip_audit_error = str(exc)
        if settings.debug:
            print(f"[debug] pip-audit findings: {len(pip_audit_report)}", file=sys.stderr)

    markdown = build_markdown(bandit_report, pip_audit_report, settings, pip_audit_error)
    write_step_summary(markdown, settings)
    emit_annotations(bandit_report, pip_audit_report, settings, pip_audit_error)

    has_blocking = bool(pip_audit_error) or check_thresholds(
        bandit_report, pip_audit_report, settings
    )

    if settings.github_token and settings.comment_on != "never":
        if settings.comment_on == "always" or has_blocking:
            upsert_pr_comment(markdown, settings)

    if pip_audit_error:
        sys.exit(f"pip-audit did NOT run, so dependencies were NOT audited.\n{pip_audit_error}")
    if has_blocking:
        sys.exit(1)


if __name__ == "__main__":
    main()
