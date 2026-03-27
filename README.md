# python-security-auditing

Reusable GitHub Action that runs [bandit](https://bandit.readthedocs.io/) and [pip-audit](https://pypi.org/project/pip-audit/) on any Python repository. Posts findings as a PR comment and fails the job when blocking issues are found.

## Usage

### Minimal (requirements.txt project)

```yaml
- uses: developmentseed/python-security-auditing@v1
```

### uv-based project

```yaml
- uses: developmentseed/python-security-auditing@v1
  with:
    package_manager: uv
    bandit_scan_dirs: 'src/,scripts/'
```

### Poetry project, stricter thresholds

```yaml
- uses: developmentseed/python-security-auditing@v1
  with:
    package_manager: poetry
    bandit_severity_threshold: medium
    pip_audit_block_on: all
```

### Bandit only (no dependency audit)

```yaml
- uses: developmentseed/python-security-auditing@v1
  with:
    tools: bandit
    bandit_scan_dirs: 'src/'
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `tools` | `bandit,pip-audit` | Comma-separated tools to run |
| `bandit_scan_dirs` | `.` | Comma-separated directories for bandit to scan |
| `bandit_severity_threshold` | `high` | Minimum severity that blocks the job: `high`, `medium`, or `low` |
| `pip_audit_block_on` | `fixable` | Block on: `fixable` (has a fix), `all`, or `none` |
| `package_manager` | `requirements` | How to resolve deps: `uv`, `pip`, `poetry`, `pipenv`, `requirements` |
| `requirements_file` | `requirements.txt` | Path when `package_manager=requirements` |
| `post_pr_comment` | `true` | Post/update a PR comment with scan results |
| `github_token` | `${{ github.token }}` | Token for PR comments |

## Outputs

- **Step summary** — written to the workflow run summary.
- **PR comment** — upserted on every run (idempotent via `<!-- security-scan-results -->` marker).
- **Artifacts** — `bandit-report.json` and `pip-audit-report.json` uploaded as `security-audit-reports`.
- **Exit code** — non-zero when blocking issues are found.

## Development

```bash
pip install -e ".[dev]"
pytest
pre-commit run --all-files
```
