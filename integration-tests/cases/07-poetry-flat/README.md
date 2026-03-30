# 07 · poetry · flat layout · clean

**Package manager**: `poetry`
**Source layout**: flat (Python files at project root)
**Expected outcome**: PASS

## What this tests

- Bandit scans the flat project directory
- No bandit issues, no vulnerable deps
- `poetry.lock` is **not committed** — tests the action's behaviour when no lockfile is present
