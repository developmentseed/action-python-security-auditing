# 06 · uv · src/+scripts/ · bandit MEDIUM

**Package manager**: `uv`
**Source layout**: `src/` + `scripts/` directories
**Expected outcome**: FAIL (bandit)

## What this tests

- Bandit scans two directories via `bandit_scan_dirs: src/,scripts/`
- MEDIUM severity threshold (lower than default HIGH) catches B324 and B506
- `uv export` produces clean deps — no pip-audit failures
- `pip_audit_block_on: none` ensures only bandit can fail this job
- `uv.lock` is committed — tests the action with a pre-existing lockfile

## Intentional issues

| File | Issue | Severity |
|------|-------|----------|
| `src/parser.py` | B506: `yaml.load()` without Loader | MEDIUM |
| `scripts/digest.py` | B324: `hashlib.md5()` | MEDIUM |
