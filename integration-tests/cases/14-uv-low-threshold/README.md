# 14 · uv · flat · low threshold (B101 assert)

**Package manager**: `uv`
**Source layout**: flat
**Expected outcome**: FAIL — bandit B101 (assert usage) blocked at low severity threshold

## What this tests
- `bandit_severity_threshold: low` — blocks on LOW severity findings
- Completes threshold coverage (high, medium, low)

## Intentional issues

| File | Issue | Severity |
|------|-------|----------|
| app.py | Use of assert detected (B101) | LOW |
