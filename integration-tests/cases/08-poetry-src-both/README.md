# 08 · poetry · src/ layout · bandit MEDIUM + pip-audit

**Package manager**: `poetry`
**Source layout**: `src/` subdirectory
**Expected outcome**: FAIL (bandit AND pip-audit)

## What this tests

- `poetry export` resolves and exports vulnerable pinned versions
- MEDIUM bandit threshold catches B324 and B105 in `src/`
- `pip_audit_block_on: all` blocks on any vulnerability (fixable or not)
- Both tools report issues simultaneously
- `poetry.lock` is **committed** — tests the action with a pre-existing lockfile

## Intentional issues

| File/Dep | Issue | Severity |
|---------|-------|---------|
| `src/auth.py` | B324: `hashlib.md5()` | MEDIUM |
| `src/auth.py` | B105: hardcoded token string | MEDIUM |
| `cryptography==38.0.0` | CVE-2023-49083 | fixable |
| `requests==2.25.0` | CVE-2023-32681 | fixable |
