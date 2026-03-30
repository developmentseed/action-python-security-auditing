# 01 · requirements · flat layout · clean

**Package manager**: `requirements`
**Source layout**: flat (Python files at project root)
**Expected outcome**: PASS

## What this tests

- Basic `requirements.txt` with pinned safe versions
- Bandit scans the flat project directory (no src/ subdirectory)
- pip-audit finds no vulnerabilities

## Action settings

| Setting | Value |
|---------|-------|
| `package_manager` | `requirements` |
| `requirements_file` | `requirements.txt` |
| `bandit_scan_dirs` | `.` |
| `bandit_severity_threshold` | `HIGH` |
| `pip_audit_block_on` | `fixable` |
