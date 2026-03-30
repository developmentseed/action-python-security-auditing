# 10 · pipenv · src/+scripts/ · bandit HIGH

**Package manager**: `pipenv`
**Source layout**: `src/` + `scripts/` directories
**Expected outcome**: FAIL (bandit)

## What this tests

- Bandit scans two directories via `bandit_scan_dirs: src/,scripts/`
- B602 (`subprocess.call(shell=True)`) in both directories triggers HIGH threshold
- Clean deps ensure only bandit fails the job
- `Pipfile.lock` is **not committed** — tests the action's behaviour when no lockfile is present

## Intentional issues

| File | Issue | Severity |
|------|-------|---------|
| `src/handler.py` | B602: `subprocess.call(shell=True)` | HIGH |
| `scripts/deploy.py` | B602: `subprocess.call(shell=True)` | HIGH |
