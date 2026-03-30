# 04 · uv · flat layout · clean

**Package manager**: `uv`
**Source layout**: flat (Python files at project root)
**Expected outcome**: PASS

## What this tests

- Bandit scans the flat project directory
- No bandit issues, no vulnerable deps
- `uv.lock` is **not committed** — tests the action's behaviour when no lockfile is present
