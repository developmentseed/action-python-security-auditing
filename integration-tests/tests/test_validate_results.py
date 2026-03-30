"""Unit tests for .github/scripts/validate_results.py.

Tests are organised by function:
  - TestParseSarif
  - TestParsePipAudit
  - TestValidateTest   (pure logic, no I/O)
  - TestGenerateReport
  - TestMain           (integration, uses tmp_path + monkeypatch)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import validate_results as vr
import yaml

# ---------------------------------------------------------------------------
# parse_sarif
# ---------------------------------------------------------------------------


class TestParseSarif:
    def test_returns_rule_id_and_level(self, tmp_path: Path, sample_sarif: dict[str, Any]) -> None:
        path = tmp_path / "results.sarif"
        path.write_text(json.dumps(sample_sarif))

        result = vr.parse_sarif(path)

        assert result == [
            {"rule_id": "B602", "level": "error"},
            {"rule_id": "B105", "level": "warning"},
        ]

    def test_empty_runs_returns_empty_list(self, tmp_path: Path) -> None:
        sarif = {"version": "2.1.0", "runs": []}
        path = tmp_path / "results.sarif"
        path.write_text(json.dumps(sarif))

        assert vr.parse_sarif(path) == []

    def test_multiple_runs_aggregates_all_findings(self, tmp_path: Path) -> None:
        sarif = {
            "version": "2.1.0",
            "runs": [
                {"results": [{"ruleId": "B101", "level": "note"}]},
                {"results": [{"ruleId": "B602", "level": "error"}]},
            ],
        }
        path = tmp_path / "results.sarif"
        path.write_text(json.dumps(sarif))

        result = vr.parse_sarif(path)

        assert len(result) == 2
        assert {r["rule_id"] for r in result} == {"B101", "B602"}

    def test_missing_fields_default_to_empty_string(self, tmp_path: Path) -> None:
        sarif: dict[str, Any] = {"runs": [{"results": [{}]}]}
        path = tmp_path / "results.sarif"
        path.write_text(json.dumps(sarif))

        result = vr.parse_sarif(path)

        assert result == [{"rule_id": "", "level": ""}]


# ---------------------------------------------------------------------------
# parse_pip_audit
# ---------------------------------------------------------------------------


class TestParsePipAudit:
    def test_returns_package_vuln_and_has_fix(
        self, tmp_path: Path, sample_pip_audit_report: dict[str, Any]
    ) -> None:
        path = tmp_path / "pip-audit-report.json"
        path.write_text(json.dumps(sample_pip_audit_report))

        result = vr.parse_pip_audit(path)

        assert len(result) == 1
        assert result[0]["package"] == "requests"
        assert result[0]["vuln_id"] == "GHSA-test-xxxx-xxxx"
        assert result[0]["has_fix"] is True

    def test_dep_with_skip_reason_is_excluded(self, tmp_path: Path) -> None:
        report = {
            "dependencies": [
                {"name": "broken-pkg", "version": "1.0", "skip_reason": "could not resolve"},
            ]
        }
        path = tmp_path / "pip-audit-report.json"
        path.write_text(json.dumps(report))

        assert vr.parse_pip_audit(path) == []

    def test_dep_with_no_vulns_returns_empty_list(self, tmp_path: Path) -> None:
        report = {
            "dependencies": [
                {"name": "requests", "version": "2.32.0", "vulns": []},
            ]
        }
        path = tmp_path / "pip-audit-report.json"
        path.write_text(json.dumps(report))

        assert vr.parse_pip_audit(path) == []

    def test_unfixable_vuln_has_fix_is_false(self, tmp_path: Path) -> None:
        report = {
            "dependencies": [
                {
                    "name": "pygments",
                    "version": "2.10.0",
                    "vulns": [{"id": "CVE-test-0001", "fix_versions": []}],
                }
            ]
        }
        path = tmp_path / "pip-audit-report.json"
        path.write_text(json.dumps(report))

        result = vr.parse_pip_audit(path)

        assert result[0]["has_fix"] is False


# ---------------------------------------------------------------------------
# validate_test  (pure logic — no filesystem I/O)
# ---------------------------------------------------------------------------


class TestValidateTest:
    def _clean_expected(self) -> dict[str, Any]:
        return {"expected_conclusion": "success", "bandit_findings": [], "pip_audit_findings": []}

    def test_missing_conclusion_returns_job_not_found_error(self) -> None:
        errors = vr.validate_test("01", self._clean_expected(), "missing", [], [])

        assert len(errors) == 1
        assert "not found" in errors[0]

    def test_matching_clean_result_returns_no_errors(self) -> None:
        errors = vr.validate_test("01", self._clean_expected(), "success", [], [])

        assert errors == []

    def test_wrong_conclusion_returns_conclusion_error(self) -> None:
        errors = vr.validate_test("01", self._clean_expected(), "failure", [], [])

        assert any("Conclusion" in e for e in errors)

    def test_expected_bandit_rule_absent_returns_error(self) -> None:
        expected = {
            "expected_conclusion": "failure",
            "bandit_findings": [{"rule_id": "B602", "level": "error"}],
            "pip_audit_findings": [],
        }

        errors = vr.validate_test(
            "02", expected, "failure", bandit_findings=[], pip_audit_findings=[]
        )

        assert any("B602" in e for e in errors)

    def test_unexpected_bandit_findings_returns_error(self) -> None:
        expected = self._clean_expected()
        bandit = [{"rule_id": "B602", "level": "error"}]

        errors = vr.validate_test("01", expected, "success", bandit, [])

        assert any("Bandit" in e for e in errors)

    def test_unexpected_bandit_rule_id_when_expected_is_nonempty_returns_error(self) -> None:
        # B404 appears in actual but is not in the expected set — must be flagged
        expected = {
            "expected_conclusion": "failure",
            "bandit_findings": [{"rule_id": "B602", "level": "error"}],
            "pip_audit_findings": [],
        }
        bandit = [
            {"rule_id": "B602", "level": "error"},
            {"rule_id": "B404", "level": "note"},
        ]

        errors = vr.validate_test("02", expected, "failure", bandit, [])

        assert any("B404" in e for e in errors)
        assert any("unexpected" in e.lower() for e in errors)

    def test_all_expected_rules_present_no_extras_returns_no_error(self) -> None:
        expected = {
            "expected_conclusion": "failure",
            "bandit_findings": [
                {"rule_id": "B602", "level": "error"},
                {"rule_id": "B404", "level": "note"},
            ],
            "pip_audit_findings": [],
        }
        bandit = [
            {"rule_id": "B602", "level": "error"},
            {"rule_id": "B404", "level": "note"},
        ]

        errors = vr.validate_test("02", expected, "failure", bandit, [])

        assert errors == []

    def test_pip_audit_has_fix_mismatch_returns_error(self) -> None:
        expected = {
            "expected_conclusion": "failure",
            "bandit_findings": [],
            "pip_audit_findings": [{"package": "requests", "has_fix": True}],
        }
        pip_audit = [{"package": "requests", "vuln_id": "CVE-test", "has_fix": False}]

        errors = vr.validate_test("05", expected, "failure", [], pip_audit)

        assert any("requests" in e for e in errors)
        assert any("fixable" in e for e in errors)

    def test_pip_audit_disabled_skips_pip_validation(self) -> None:
        expected = {
            "expected_conclusion": "failure",
            "pip_audit_disabled": True,
            "bandit_findings": [{"rule_id": "B602", "level": "error"}],
            "pip_audit_findings": [],
        }
        bandit = [{"rule_id": "B602", "level": "error"}]
        # pip_audit has unexpected findings — should be ignored because pip_audit_disabled=True
        pip_audit = [{"package": "requests", "vuln_id": "CVE-test", "has_fix": True}]

        errors = vr.validate_test("12", expected, "failure", bandit, pip_audit)

        assert errors == []

    def test_expected_pip_audit_package_absent_returns_error(self) -> None:
        expected = {
            "expected_conclusion": "failure",
            "bandit_findings": [],
            "pip_audit_findings": [{"package": "requests", "has_fix": True}],
        }

        errors = vr.validate_test("05", expected, "failure", [], pip_audit_findings=[])

        assert any("requests" in e for e in errors)


# ---------------------------------------------------------------------------
# generate_report
# ---------------------------------------------------------------------------


class TestGenerateReport:
    def _minimal_expected(self, nums: list[str]) -> dict[str, Any]:
        return {"tests": {n: {"name": f"test-{n}", "expected_conclusion": "success"} for n in nums}}

    def test_all_pass_shows_success_header(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(vr, "EXPECTED_COUNT", 2)
        expected = self._minimal_expected(["01", "02"])
        conclusions = {"01": "success", "02": "success"}
        all_errors: dict[str, list[str]] = {"01": [], "02": []}

        report = vr.generate_report(expected, conclusions, {}, {}, all_errors)

        assert "✅" in report
        assert "All test workflows" in report

    def test_failures_shows_failure_header_and_error_details(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(vr, "EXPECTED_COUNT", 2)
        expected = self._minimal_expected(["01", "02"])
        conclusions = {"01": "success", "02": "failure"}
        all_errors: dict[str, list[str]] = {
            "01": [],
            "02": ["Conclusion: expected success, got failure"],
        }

        report = vr.generate_report(expected, conclusions, {}, {}, all_errors)

        assert "❌" in report
        assert "Error details" in report
        assert "Conclusion: expected success, got failure" in report


# ---------------------------------------------------------------------------
# main() integration
# ---------------------------------------------------------------------------


class TestMain:
    """Integration tests for main(). Uses tmp_path to avoid real filesystem side-effects."""

    def _write_expected_yml(self, base: Path, tests: dict[str, Any]) -> None:
        (base / "expected_results.yml").write_text(yaml.dump({"tests": tests}))

    def test_happy_path_returns_zero(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        tests = {
            "01": {
                "name": "clean",
                "expected_conclusion": "success",
                "bandit_findings": [],
                "pip_audit_findings": [],
            },
            "02": {
                "name": "bandit-high",
                "expected_conclusion": "failure",
                "bandit_findings": [{"rule_id": "B602", "level": "error"}],
                "pip_audit_findings": [],
            },
        }
        self._write_expected_yml(tmp_path, tests)

        # Test 01: clean SARIF, no pip-audit artifact
        art01 = tmp_path / "artifacts" / "security-audit-01"
        art01.mkdir(parents=True)
        (art01 / "results.sarif").write_text(json.dumps({"runs": [{"results": []}]}))

        # Test 02: B602 finding in SARIF
        art02 = tmp_path / "artifacts" / "security-audit-02"
        art02.mkdir(parents=True)
        sarif02 = {"runs": [{"results": [{"ruleId": "B602", "level": "error"}]}]}
        (art02 / "results.sarif").write_text(json.dumps(sarif02))

        needs = {"test-01": {"result": "success"}, "test-02": {"result": "failure"}}
        monkeypatch.setenv("NEEDS_JSON", json.dumps(needs))
        monkeypatch.setattr(vr, "EXPECTED_COUNT", 2)
        monkeypatch.setattr(vr, "ARTIFACTS_DIR", tmp_path / "artifacts")
        monkeypatch.setattr(vr, "EXPECTED_RESULTS_PATH", tmp_path / "expected_results.yml")
        monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
        monkeypatch.chdir(tmp_path)

        assert vr.main() == 0

    def test_conclusion_mismatch_returns_one(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tests = {
            "01": {
                "name": "expected-success",
                "expected_conclusion": "success",
                "bandit_findings": [],
                "pip_audit_findings": [],
            },
        }
        self._write_expected_yml(tmp_path, tests)

        art01 = tmp_path / "artifacts" / "security-audit-01"
        art01.mkdir(parents=True)

        # Report failure but expected success
        needs = {"test-01": {"result": "failure"}}
        monkeypatch.setenv("NEEDS_JSON", json.dumps(needs))
        monkeypatch.setattr(vr, "EXPECTED_COUNT", 1)
        monkeypatch.setattr(vr, "ARTIFACTS_DIR", tmp_path / "artifacts")
        monkeypatch.setattr(vr, "EXPECTED_RESULTS_PATH", tmp_path / "expected_results.yml")
        monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
        monkeypatch.chdir(tmp_path)

        assert vr.main() == 1
