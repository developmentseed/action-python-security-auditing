"""Validate that all 14 test workflows produced the expected outcomes.

Reads job conclusions from the NEEDS_JSON env var (set by
integration-tests.yml via ``${{ toJSON(needs) }}``) and parses
downloaded artifacts (SARIF + pip-audit JSON) from the local filesystem.

Writes a markdown report to validation-report.md and $GITHUB_STEP_SUMMARY.

Required env var:  NEEDS_JSON
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

EXPECTED_COUNT = 14
ARTIFACTS_DIR = Path("artifacts")
EXPECTED_RESULTS_PATH = Path(__file__).parent / "expected_results.yml"

# ---------------------------------------------------------------------------
# Artifact parsing
# ---------------------------------------------------------------------------


def parse_sarif(path: Path) -> list[dict[str, str]]:
    """Parse bandit SARIF and return list of {rule_id, level}."""
    sarif = json.loads(path.read_bytes())
    results = []
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            results.append(
                {
                    "rule_id": result.get("ruleId", ""),
                    "level": result.get("level", ""),
                }
            )
    return results


def parse_pip_audit(path: Path) -> list[dict[str, Any]]:
    """Parse pip-audit JSON and return list of vulnerable packages."""
    report = json.loads(path.read_bytes())
    findings: list[dict[str, Any]] = []
    for dep in report.get("dependencies", []):
        if "skip_reason" in dep:
            continue
        for vuln in dep.get("vulns", []):
            findings.append(
                {
                    "package": dep["name"],
                    "vuln_id": vuln.get("id", ""),
                    "has_fix": len(vuln.get("fix_versions", [])) > 0,
                }
            )
    return findings


# ---------------------------------------------------------------------------
# Comparison logic
# ---------------------------------------------------------------------------


def validate_test(
    test_num: str,
    expected: dict[str, Any],
    conclusion: str,
    bandit_findings: list[dict[str, str]],
    pip_audit_findings: list[dict[str, Any]],
) -> list[str]:
    """Compare actual vs expected for one test. Returns list of error messages."""
    errors: list[str] = []

    # --- Conclusion ---
    if conclusion == "missing":
        errors.append(f"Job not found for test {test_num}")
        return errors

    expected_conclusion = expected["expected_conclusion"]
    if conclusion != expected_conclusion:
        errors.append(f"Conclusion: expected {expected_conclusion}, got {conclusion}")

    # --- Bandit findings ---
    expected_bandit = expected.get("bandit_findings", [])
    actual_rule_ids = {f["rule_id"] for f in bandit_findings}
    expected_rule_ids = {e["rule_id"] for e in expected_bandit}

    if not expected_bandit and bandit_findings:
        errors.append(
            f"Bandit: expected no findings, got {len(bandit_findings)} "
            f"({', '.join(sorted(actual_rule_ids))})"
        )
    for exp in expected_bandit:
        if exp["rule_id"] not in actual_rule_ids:
            errors.append(f"Bandit: expected {exp['rule_id']} not found in results")
    if expected_bandit:
        unexpected = sorted(actual_rule_ids - expected_rule_ids)
        if unexpected:
            errors.append(
                f"Bandit: unexpected finding(s) not in expected set: {', '.join(unexpected)}"
            )

    # --- pip-audit findings ---
    pip_audit_disabled = expected.get("pip_audit_disabled", False)
    if not pip_audit_disabled:
        expected_pip = expected.get("pip_audit_findings", [])
        actual_packages = {f["package"].lower() for f in pip_audit_findings}
        actual_by_package: dict[str, list[dict[str, Any]]] = {}
        for f in pip_audit_findings:
            actual_by_package.setdefault(f["package"].lower(), []).append(f)

        if not expected_pip and pip_audit_findings:
            errors.append(
                f"pip-audit: expected no vulns, got {len(pip_audit_findings)} "
                f"({', '.join(sorted(actual_packages))})"
            )
        for exp in expected_pip:
            pkg = exp["package"].lower()
            if pkg not in actual_packages:
                errors.append(f"pip-audit: expected vuln for {exp['package']} not found")
            elif "has_fix" in exp:
                actual_has_fix = any(f["has_fix"] for f in actual_by_package[pkg])
                if exp["has_fix"] != actual_has_fix:
                    fix_label = "fixable" if exp["has_fix"] else "unfixable"
                    errors.append(
                        f"pip-audit: {exp['package']} expected {fix_label}, "
                        f"got {'fixable' if actual_has_fix else 'unfixable'}"
                    )

    return errors


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


# Unique marker so the workflow can find & update this comment
COMMENT_MARKER = "<!-- integration-test-validation-report -->"


def generate_report(
    expected_results: dict[str, Any],
    conclusions: dict[str, str],
    all_bandit: dict[str, list[dict[str, str]]],
    all_pip_audit: dict[str, list[dict[str, Any]]],
    all_errors: dict[str, list[str]],
) -> str:
    """Generate a markdown report summarising validation results."""
    lines: list[str] = [COMMENT_MARKER, ""]
    total_pass = sum(1 for errs in all_errors.values() if not errs)
    total_fail = sum(1 for errs in all_errors.values() if errs)
    total_missing = EXPECTED_COUNT - len(conclusions)

    if total_fail == 0 and total_missing == 0:
        lines.append("## ✅ All test workflows behaved as expected\n")
    else:
        lines.append("## ❌ Some test workflows did not match expectations\n")

    lines.append(f"**{total_pass}** passed, **{total_fail}** failed")
    if total_missing:
        lines.append(f", **{total_missing}** missing")
    lines.append("\n")

    # Summary table
    lines.append("| Test | Name | Expected | Actual | Bandit | pip-audit | Result |")
    lines.append("|------|------|----------|--------|--------|-----------|--------|")

    for num in sorted(expected_results["tests"].keys()):
        exp = expected_results["tests"][num]
        name = exp.get("name", num)
        exp_conclusion = exp["expected_conclusion"]
        actual_conclusion = conclusions.get(num, "missing")
        errs = all_errors.get(num, ["not checked"])

        bandit = all_bandit.get(num, [])
        pip = all_pip_audit.get(num, [])
        bandit_summary = ", ".join(sorted({f["rule_id"] for f in bandit})) or "—"
        pip_summary = ", ".join(sorted({f["package"] for f in pip})) or "—"
        if exp.get("pip_audit_disabled"):
            pip_summary = "disabled"

        result = "✅" if not errs else "❌"
        lines.append(
            f"| {num} | {name} | {exp_conclusion} | {actual_conclusion} "
            f"| {bandit_summary} | {pip_summary} | {result} |"
        )

    # Error details
    any_errors = {k: v for k, v in all_errors.items() if v}
    if any_errors:
        lines.append("\n### Error details\n")
        for num in sorted(any_errors.keys()):
            exp = expected_results["tests"][num]
            lines.append(f"**Test {num}** — {exp.get('name', num)}")
            for err in any_errors[num]:
                lines.append(f"- {err}")
            lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    # Load expected results
    with open(EXPECTED_RESULTS_PATH) as f:
        expected_results: dict[str, Any] = yaml.safe_load(f)

    tests = expected_results["tests"]
    if len(tests) != EXPECTED_COUNT:
        print(
            f"ERROR: expected_results.yml has {len(tests)} tests, expected {EXPECTED_COUNT}",
            file=sys.stderr,
        )
        return 1

    # Read job conclusions from the needs context
    needs_json = json.loads(os.environ["NEEDS_JSON"])
    conclusions: dict[str, str] = {}
    for job_name, job_data in needs_json.items():
        parts = job_name.split("-")
        if len(parts) == 2 and parts[0] == "test":
            conclusions[parts[1]] = job_data["result"]

    # Parse artifacts from local filesystem
    all_bandit: dict[str, list[dict[str, str]]] = {}
    all_pip_audit: dict[str, list[dict[str, Any]]] = {}
    all_errors: dict[str, list[str]] = {}

    for num in sorted(tests.keys()):
        exp = tests[num]
        artifact_dir = ARTIFACTS_DIR / f"security-audit-{num}"

        bandit_findings: list[dict[str, str]] = []
        pip_audit_findings: list[dict[str, Any]] = []

        sarif_path = artifact_dir / "results.sarif"
        if sarif_path.exists():
            bandit_findings = parse_sarif(sarif_path)

        pip_audit_path = artifact_dir / "pip-audit-report.json"
        if pip_audit_path.exists():
            pip_audit_findings = parse_pip_audit(pip_audit_path)
        else:
            # Artifact upload uses least common ancestor, so the file may be nested
            # e.g. artifacts/security-audit-08/08-poetry-src-both/pip-audit-report.json
            nested = next(artifact_dir.rglob("pip-audit-report.json"), None)
            if nested:
                pip_audit_findings = parse_pip_audit(nested)

        all_bandit[num] = bandit_findings
        all_pip_audit[num] = pip_audit_findings

        conclusion = conclusions.get(num, "missing")
        errors = validate_test(num, exp, conclusion, bandit_findings, pip_audit_findings)
        all_errors[num] = errors

        status = "✅" if not errors else "❌"
        print(f"  [{num}] {status} {exp.get('name', num)}")
        for err in errors:
            print(f"         {err}")

    # Generate report
    report = generate_report(expected_results, conclusions, all_bandit, all_pip_audit, all_errors)

    # Write report to file for PR comment step
    report_path = Path("validation-report.md")
    report_path.write_text(report)
    print(f"\nReport written to {report_path}")

    # Write to step summary if available
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a") as f:
            f.write(report)

    print("\n" + report)

    has_failures = any(errs for errs in all_errors.values())
    has_missing = len(conclusions) < EXPECTED_COUNT
    return 1 if has_failures or has_missing else 0


if __name__ == "__main__":
    sys.exit(main())
