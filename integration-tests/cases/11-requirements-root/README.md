# 11 · requirements · flat · clean (root working dir)

**Package manager**: `requirements`
**Source layout**: flat
**Expected outcome**: PASS — no bandit issues, no vulnerable dependencies

## What this tests
- Default `working_directory` (`.`) — omitted from action inputs
- `bandit_scan_dirs` pointed at a specific clean folder
- Validates the passthrough path when no working_directory prefix is needed

## Action settings

| Setting | Value |
|---------|-------|
| `package_manager` | requirements |
| `requirements_file` | 11-requirements-root/requirements.txt |
| `bandit_scan_dirs` | 11-requirements-root |
| `bandit_severity_threshold` | high |
| `pip_audit_block_on` | fixable |
| `working_directory` | *(default: `.`)* |
