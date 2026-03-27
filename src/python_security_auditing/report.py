"""Markdown report builder and threshold checker."""

from __future__ import annotations

from typing import Any

from .settings import Settings

_SEVERITY_ICON = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}


def build_markdown(
    bandit_report: dict[str, Any],
    pip_audit_report: list[dict[str, Any]],
    settings: Settings,
) -> str:
    """Build a full markdown security report."""
    sections: list[str] = ["# Security Audit Report\n"]

    run_url = (
        f"https://github.com/{settings.github_repository}/actions/runs/{settings.github_run_id}"
        if settings.github_repository and settings.github_run_id
        else ""
    )
    if run_url:
        sections.append(f"[View workflow run]({run_url})\n")

    if "bandit" in settings.enabled_tools:
        sections.append(_bandit_section(bandit_report, settings))

    if "pip-audit" in settings.enabled_tools:
        sections.append(_pip_audit_section(pip_audit_report, settings))

    blocking = check_thresholds(bandit_report, pip_audit_report, settings)
    sections.append("---\n")
    if blocking:
        sections.append("**Result: ❌ Blocking issues found — see details above.**\n")
    else:
        sections.append("**Result: ✅ No blocking issues found.**\n")

    return "\n".join(sections)


def _bandit_section(report: dict[str, Any], settings: Settings) -> str:
    results: list[dict[str, Any]] = report.get("results", [])
    lines = ["## Bandit — Static Security Analysis\n"]

    if not results:
        lines.append("✅ No issues found.\n")
        return "\n".join(lines)

    lines.append("| Severity | Confidence | File | Line | Issue |\n" "|---|---|---|---|---|\n")
    for r in results:
        sev = r.get("issue_severity", "")
        conf = r.get("issue_confidence", "")
        icon = _SEVERITY_ICON.get(sev, "")
        fname = r.get("filename", "")
        line = r.get("line_number", "")
        text = r.get("issue_text", "").replace("|", "\\|")
        test_id = r.get("test_id", "")
        lines.append(f"| {icon} {sev} | {conf} | `{fname}` | {line} | [{test_id}] {text} |")

    blocking_results = [
        r for r in results if r.get("issue_severity") in settings.blocking_severities
    ]
    lines.append(
        f"\n_{len(results)} issue(s) found, "
        f"{len(blocking_results)} at or above {settings.bandit_severity_threshold.upper()} threshold._\n"
    )
    return "\n".join(lines)


def _pip_audit_section(report: list[dict[str, Any]], settings: Settings) -> str:
    vulnerable = [pkg for pkg in report if pkg.get("vulns")]
    lines = ["## pip-audit — Dependency Vulnerabilities\n"]

    if not vulnerable:
        lines.append("✅ No vulnerabilities found.\n")
        return "\n".join(lines)

    lines.append(
        "| Package | Version | ID | Fix Versions | Description |\n" "|---|---|---|---|---|\n"
    )
    for pkg in vulnerable:
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        for vuln in pkg.get("vulns", []):
            vid = vuln.get("id", "")
            fix_versions = ", ".join(vuln.get("fix_versions", [])) or "none"
            desc = (vuln.get("description", "") or "")[:120].replace("|", "\\|")
            lines.append(f"| {name} | {version} | {vid} | {fix_versions} | {desc} |")

    total_vulns = sum(len(pkg.get("vulns", [])) for pkg in vulnerable)
    fixable = sum(1 for pkg in vulnerable for v in pkg.get("vulns", []) if v.get("fix_versions"))
    lines.append(
        f"\n_{total_vulns} vulnerability/vulnerabilities found "
        f"({fixable} fixable) across {len(vulnerable)} package(s)._\n"
    )
    return "\n".join(lines)


def check_thresholds(
    bandit_report: dict[str, Any],
    pip_audit_report: list[dict[str, Any]],
    settings: Settings,
) -> bool:
    """Return True if any blocking issues were found."""
    if "bandit" in settings.enabled_tools:
        for result in bandit_report.get("results", []):
            if result.get("issue_severity") in settings.blocking_severities:
                return True

    if "pip-audit" in settings.enabled_tools:
        block_on = settings.pip_audit_block_on
        if block_on == "none":
            pass
        elif block_on == "all":
            for pkg in pip_audit_report:
                if pkg.get("vulns"):
                    return True
        elif block_on == "fixable":
            for pkg in pip_audit_report:
                for vuln in pkg.get("vulns", []):
                    if vuln.get("fix_versions"):
                        return True

    return False


def write_step_summary(markdown: str, settings: Settings) -> None:
    """Append the markdown report to the GitHub step summary file."""
    if not settings.github_step_summary:
        return
    with open(settings.github_step_summary, "a") as f:
        f.write(markdown)
        f.write("\n")
