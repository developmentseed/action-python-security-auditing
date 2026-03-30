# 12 · uv · flat · bandit-only (no pip-audit)

**Package manager**: `uv`
**Source layout**: flat
**Expected outcome**: FAIL — bandit finds B602 (subprocess with shell=True)

## What this tests
- `tools: bandit` — pip-audit fully disabled, not just `block_on: none`
- Validates that bandit-only mode works correctly

## Intentional issues

| File | Issue | Severity |
|------|-------|----------|
| app.py | subprocess call with shell=True (B602) | HIGH |
