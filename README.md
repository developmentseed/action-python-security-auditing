# python-security-auditing

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/lhoupert/action-python-security-auditing/badge)](https://scorecard.dev/viewer/?uri=github.com/lhoupert/action-python-security-auditing)

A GitHub Action that runs **[bandit](https://bandit.readthedocs.io/)** (static code analysis) and **[pip-audit](https://pypi.org/project/pip-audit/)** (dependency vulnerability scanning) on a Python repository, then puts the results in one PR comment, the workflow step summary, and a downloadable artifact.

## When this might be useful

Running bandit and pip-audit directly—or using focused actions like `PyCQA/bandit-action` or `pypa/gh-action-pip-audit`—is a reasonable and common approach. Those tools and actions are fine on their own.

This repo exists for workflows where you want **both** scanners behind **one** job and **one** place to read the outcome. It is a thin wrapper around the same tools, not a different kind of analysis. The things it adds on top of running the tools individually:

- **One PR comment for both scanners** — created on the first run and updated in place on every subsequent push, so the PR thread stays clean.
- **Workflow step summary** — the same report is written to the "Summary" tab of the workflow run.
- **Block on fixable-only vulnerabilities** — `pip_audit_block_on: fixable` (the default) fails CI only when a patched version exists, so you can act on it immediately; unfixable CVEs are reported but don't block.
- **Automatic requirements export** — pass `package_manager: uv|poetry|pipenv` and the action runs the appropriate export command before invoking pip-audit, saving you an extra workflow step.

## What the PR comment looks like

When issues are found, the comment posted to the PR looks like this:

```
# Security Audit Report

## Bandit — Static Security Analysis

| Severity | Confidence | File | Line | Issue |
|---|---|---|---|---|
| 🔴 HIGH | HIGH | `src/app.py` | 2 | [B404] Consider possible security implications associated with subprocess module. |
| 🟡 MEDIUM | MEDIUM | `src/app.py` | 5 | [B602] subprocess call with shell=True identified, security issue. |

_2 issue(s) found, 1 at or above HIGH threshold._

## pip-audit — Dependency Vulnerabilities

| Package | Version | ID | Fix Versions | Description |
|---|---|---|---|---|
| requests | 2.25.0 | GHSA-j8r2-6x86-q33q | 2.31.0 | Unintended leak of Proxy-Authorization header ... |

_1 vulnerability/vulnerabilities found (1 fixable) across 1 package(s)._

---
**Result: ❌ Blocking issues found — see details above.**
```

When everything is clean:

```
## Bandit — Static Security Analysis
✅ No issues found.

## pip-audit — Dependency Vulnerabilities
✅ No vulnerabilities found.

---
**Result: ✅ No blocking issues found.**
```

The comment is idempotent — it is created once and updated in place on every push, so the PR thread stays clean.

## Quickstart

Add this to your workflow (e.g. `.github/workflows/security.yml`):

```yaml
name: Security Audit

on:
  pull_request:
  push:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
      - uses: lhoupert/action-python-security-auditing@12efad3bddc3efd3668cf6ac6799f94837f4fb3d # v0.5.0
```

This runs both bandit and pip-audit with sensible defaults: blocks the job on HIGH-severity code issues and on dependency vulnerabilities that have a fix available.

## Usage examples

### uv project

```yaml
- uses: lhoupert/action-python-security-auditing@12efad3bddc3efd3668cf6ac6799f94837f4fb3d # v0.5.0
  with:
    package_manager: uv
    bandit_scan_dirs: 'src/'
```

### Poetry project with stricter thresholds

Block on any bandit finding at MEDIUM or above, and on all known vulnerabilities regardless of whether a fix exists:

```yaml
- uses: lhoupert/action-python-security-auditing@12efad3bddc3efd3668cf6ac6799f94837f4fb3d # v0.5.0
  with:
    package_manager: poetry
    bandit_severity_threshold: medium
    pip_audit_block_on: all
```

### Bandit only (skip dependency audit)

Useful when you manage dependencies externally or run pip-audit in a separate job:

```yaml
- uses: lhoupert/action-python-security-auditing@12efad3bddc3efd3668cf6ac6799f94837f4fb3d # v0.5.0
  with:
    tools: bandit
    bandit_scan_dirs: 'src/'
```

### Project in a subdirectory (monorepo)

```yaml
- uses: lhoupert/action-python-security-auditing@12efad3bddc3efd3668cf6ac6799f94837f4fb3d # v0.5.0
  with:
    working_directory: services/api
    package_manager: uv
    bandit_scan_dirs: 'src/'
```

### Audit-only mode (never block the job)

Run the audit and post the comment for visibility, but don't fail CI:

```yaml
- uses: lhoupert/action-python-security-auditing@12efad3bddc3efd3668cf6ac6799f94837f4fb3d # v0.5.0
  with:
    bandit_severity_threshold: low   # report everything
    pip_audit_block_on: none         # never block
```

## How blocking works

The job fails (non-zero exit) when **either** tool finds issues above its configured threshold.

**Bandit threshold** (`bandit_severity_threshold`): findings at or above the threshold block the job.

| `bandit_severity_threshold` | Blocks on |
|---|---|
| `high` (default) | 🔴 HIGH only |
| `medium` | 🟡 MEDIUM and 🔴 HIGH |
| `low` | 🟢 LOW, 🟡 MEDIUM, and 🔴 HIGH |

**pip-audit threshold** (`pip_audit_block_on`):

| `pip_audit_block_on` | Blocks on |
|---|---|
| `fixable` (default) | Vulnerabilities with a fix available — you can act on these immediately |
| `all` | All known vulnerabilities, including those with no fix yet |
| `none` | Never blocks — audit runs but CI stays green |

## Inputs

| Input | Default | Description |
|---|---|---|
| `tools` | `bandit,pip-audit` | Comma-separated tools to run |
| `bandit_scan_dirs` | `.` | Comma-separated directories for bandit to scan (relative to `working_directory`) |
| `bandit_severity_threshold` | `high` | Minimum severity that blocks the job: `high`, `medium`, or `low` |
| `pip_audit_block_on` | `fixable` | When pip-audit findings block the job: `fixable`, `all`, or `none` |
| `package_manager` | `requirements` | How to resolve deps for pip-audit: `uv`, `pip`, `poetry`, `pipenv`, `requirements` |
| `requirements_file` | `requirements.txt` | Path to requirements file when `package_manager=requirements` |
| `working_directory` | `.` | Directory to run the audit from (useful for monorepos) |
| `post_pr_comment` | `true` | Post/update a PR comment with scan results |
| `github_token` | `${{ github.token }}` | Token used for posting PR comments |
| `artifact_name` | `security-audit-reports` | Name of the uploaded artifact |

## Outputs

- **PR comment** — created on first run, updated in place on every subsequent run. The comment is keyed on a hidden `<!-- security-scan-results::{workflow-name} -->` marker, so multiple workflows on the same PR each maintain their own separate comment.
- **Step summary** — the same report is written to the workflow run summary, visible under the "Summary" tab.
- **Artifact** — `pip-audit-report.json` and `results.sarif` uploaded under the name set by `artifact_name` (default: `security-audit-reports`) for download or downstream steps.
- **Exit code** — non-zero when blocking issues are found, so the job fails and branch protections can enforce it.

## Development

```bash
uv pip install -e ".[dev]"
uv run pytest
pre-commit run --all-files
```
