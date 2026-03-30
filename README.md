# python-security-auditing

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/lhoupert/action-python-security-auditing/badge)](https://scorecard.dev/viewer/?uri=github.com/lhoupert/action-python-security-auditing)

A GitHub Action that runs **[bandit](https://bandit.readthedocs.io/)** (static code analysis) and **[pip-audit](https://pypi.org/project/pip-audit/)** (dependency vulnerability scanning) on a Python repository, then puts the results in one PR comment, the workflow step summary, and a downloadable artifact.

## When this might be useful

Running bandit and pip-audit directly — or using the official focused actions ([PyCQA/bandit-action](https://github.com/PyCQA/bandit-action) and [pypa/gh-action-pip-audit](https://github.com/pypa/gh-action-pip-audit)) — is a reasonable and common approach. Those tools and actions are fine on their own.

This action exists for workflows where you want **both** scanners behind **one** step and **one** place to read the outcome. It is a thin wrapper around the same tools, not a different kind of analysis. The things it adds on top of running the tools individually:

- **Single step, unified report** — one action replaces two, with no need to coordinate SARIF uploads or chain step outputs between jobs.
- **One PR comment for both scanners** — created on the first run and updated in place on every subsequent push, so the PR thread stays clean. Neither official action provides this out of the box.
- **Workflow step summary** — the same report is written to the "Summary" tab of the workflow run.
- **Block on fixable-only vulnerabilities** — `pip_audit_block_on: fixable` (the default) fails CI only when a patched version exists, so you can act on it immediately; unfixable CVEs are reported but don't block. The official pip-audit action does not have this mode.
- **Automatic requirements export** — pass `package_manager: uv|poetry|pipenv` and the action runs the appropriate export command before invoking pip-audit. With the official pip-audit action, you must add a separate step to export first.

### Comparison with running the tools separately

**Using the two official actions (uv project, bandit + pip-audit):**

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4

      # Static analysis
      - uses: PyCQA/bandit-action@v1
        with:
          targets: src/

      # Export dependencies before pip-audit (required for uv projects)
      - name: Export requirements
        run: uv export --no-dev --format requirements-txt > requirements.txt

      # Dependency audit
      - uses: pypa/gh-action-pip-audit@v1
        with:
          inputs: requirements.txt
          # Note: no built-in "fixable-only" blocking mode
          # Note: findings appear only in the Actions log — no PR comment
```

**Using this action (equivalent result, one step):**

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write   # for the unified PR comment
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: lhoupert/action-python-security-auditing@12efad3bddc3efd3668cf6ac6799f94837f4fb3d # v0.5.0
        with:
          package_manager: uv        # export handled automatically
          bandit_scan_dirs: 'src/'
          pip_audit_block_on: fixable  # only block when a fix exists
          # Posts a unified PR comment and step summary automatically
```

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

Each section also includes a direct link: the Bandit section links to the repository's GitHub Code Scanning page, and the pip-audit section links to the Dependabot security alerts page. These links appear when GitHub repository context is available (i.e. when running inside a GitHub Actions workflow).

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

## Required permissions

The action needs these permissions on the job:

```yaml
permissions:
  contents: read
  pull-requests: write   # post/update the PR comment (when post_pr_comment: true)
  security-events: write # upload bandit SARIF to GitHub Code Scanning
```

If you only use `post_pr_comment: false` and don't care about Code Scanning integration, `contents: read` alone is sufficient.

## Usage examples

### Choosing a package manager

Pass `package_manager` to match how your project manages dependencies. The action exports a requirements list before invoking pip-audit, so no extra step is needed.

**uv:**
```yaml
- uses: lhoupert/action-python-security-auditing@12efad3bddc3efd3668cf6ac6799f94837f4fb3d # v0.5.0
  with:
    package_manager: uv
    bandit_scan_dirs: 'src/'
```

**Poetry:**
```yaml
- uses: lhoupert/action-python-security-auditing@12efad3bddc3efd3668cf6ac6799f94837f4fb3d # v0.5.0
  with:
    package_manager: poetry
    bandit_scan_dirs: 'src/'
```

**Pipenv:**
```yaml
- uses: lhoupert/action-python-security-auditing@12efad3bddc3efd3668cf6ac6799f94837f4fb3d # v0.5.0
  with:
    package_manager: pipenv
    bandit_scan_dirs: 'src/'
```

**Plain requirements file (default):**
```yaml
- uses: lhoupert/action-python-security-auditing@12efad3bddc3efd3668cf6ac6799f94837f4fb3d # v0.5.0
  with:
    requirements_file: requirements/prod.txt
    bandit_scan_dirs: 'src/'
```

### Scanning multiple directories

When your source code spans more than one directory, pass a comma-separated list to `bandit_scan_dirs`:

```yaml
- uses: lhoupert/action-python-security-auditing@12efad3bddc3efd3668cf6ac6799f94837f4fb3d # v0.5.0
  with:
    package_manager: uv
    bandit_scan_dirs: 'src/,scripts/'
```

### Project in a subdirectory (monorepo)

Set `working_directory` to the project root within the repo. All relative paths (scan dirs, requirements file) are resolved from there:

```yaml
- uses: lhoupert/action-python-security-auditing@12efad3bddc3efd3668cf6ac6799f94837f4fb3d # v0.5.0
  with:
    working_directory: services/api
    package_manager: uv
    bandit_scan_dirs: 'src/'
```

### Bandit only (skip dependency audit)

Useful when you manage dependencies externally or run pip-audit in a separate job:

```yaml
- uses: lhoupert/action-python-security-auditing@12efad3bddc3efd3668cf6ac6799f94837f4fb3d # v0.5.0
  with:
    tools: bandit
    bandit_scan_dirs: 'src/'
```

### Dependency audit only (skip static analysis)

Useful when you already run bandit separately or only care about known CVEs in dependencies:

```yaml
- uses: lhoupert/action-python-security-auditing@12efad3bddc3efd3668cf6ac6799f94837f4fb3d # v0.5.0
  with:
    tools: pip-audit
    package_manager: uv
```

### Strict security gate

Block on any bandit finding at MEDIUM or above, and on all known vulnerabilities regardless of whether a fix exists. Suitable for high-assurance services or regulated environments:

```yaml
- uses: lhoupert/action-python-security-auditing@12efad3bddc3efd3668cf6ac6799f94837f4fb3d # v0.5.0
  with:
    package_manager: poetry
    bandit_severity_threshold: medium
    pip_audit_block_on: all
```

### Gradual adoption (audit-only, never block)

Add the action first as an observer: it posts findings to the PR comment and step summary without ever failing the job. Tighten the thresholds once your team has addressed the backlog:

```yaml
- uses: lhoupert/action-python-security-auditing@12efad3bddc3efd3668cf6ac6799f94837f4fb3d # v0.5.0
  with:
    package_manager: uv
    bandit_severity_threshold: low   # report everything
    pip_audit_block_on: none         # never block
```

### Scheduled scan on the default branch

Run a weekly audit against `main` in addition to PR checks, so vulnerabilities introduced through dependency updates are caught promptly:

```yaml
name: Weekly Security Audit

on:
  schedule:
    - cron: '0 8 * * 1'  # every Monday at 08:00 UTC
  push:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: lhoupert/action-python-security-auditing@12efad3bddc3efd3668cf6ac6799f94837f4fb3d # v0.5.0
        with:
          package_manager: uv
          post_pr_comment: false   # no PR to comment on for scheduled runs
```

### Multiple workflows posting separate PR comments

If you run this action from more than one workflow on the same PR (e.g. a general security workflow and a focused API service workflow), each workflow automatically gets its own PR comment. No configuration is needed — the comment is keyed on the workflow name, so the two comments stay independent and update in place separately.

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
| `debug` | `false` | Enable verbose debug logging; also activates automatically when re-running a workflow with "Enable debug logging" |

## Outputs

- **PR comment** — created on first run, updated in place on every subsequent run. The comment is keyed on a hidden `<!-- security-scan-results::{workflow-name} -->` marker, so multiple workflows on the same PR each maintain their own separate comment.
- **Step summary** — the same report is written to the workflow run summary, visible under the "Summary" tab.
- **Artifact** — `pip-audit-report.json` and `results.sarif` uploaded under the name set by `artifact_name` (default: `security-audit-reports`) for download or downstream steps. The `results.sarif` file is the bandit SARIF report; it is also uploaded to GitHub Code Scanning automatically by the underlying `lhoupert/bandit-action` step, making findings visible in the repository's Security tab when the job has `security-events: write` permission.
- **Exit code** — non-zero when blocking issues are found, so the job fails and branch protections can enforce it.

## Development

```bash
uv pip install -e ".[dev]"
uv run pytest
pre-commit run --all-files
```
