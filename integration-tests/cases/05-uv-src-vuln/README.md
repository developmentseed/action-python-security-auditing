# 05 · uv · src/ layout · pip-audit vuln

**Package manager**: `uv`
**Source layout**: `src/` subdirectory
**Expected outcome**: FAIL (pip-audit)

## What this tests

- `uv export` resolves and exports `requests==2.25.0` from `uv.lock`
- pip-audit detects the fixable CVE-2023-32681 in `requests==2.25.0`
- Bandit finds no issues in clean code
- Workflow fails due to pip-audit finding a fixable vulnerability
- `uv.lock` is **committed** — required so pip-audit reliably resolves the pinned vulnerable version

## Intentional issues

| Dependency | Version | CVE |
|-----------|---------|-----|
| `requests` | `2.25.0` | CVE-2023-32681 (fixable — upgrade to ≥2.31.0) |
