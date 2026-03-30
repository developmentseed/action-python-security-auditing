# 02 · requirements · src/ layout · bandit HIGH

**Package manager**: `requirements`
**Source layout**: `src/` subdirectory
**Expected outcome**: FAIL (bandit)

## What this tests

- Bandit correctly scans `src/` subdirectory only
- B602 (`subprocess.call(shell=True)`) is detected as HIGH severity
- B105 (hardcoded password) is detected as MEDIUM severity
- Workflow fails because B602 meets the HIGH threshold

## Intentional issues

| File | Issue | Severity |
|------|-------|---------|
| `src/app.py` | B602: `subprocess.call(cmd, shell=True)` | HIGH |
| `src/app.py` | B105: hardcoded password string | MEDIUM |
