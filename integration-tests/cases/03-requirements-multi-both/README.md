# 03 · requirements · src/+scripts/ · bandit HIGH + pip-audit

**Package manager**: `requirements`
**Source layout**: `src/` + `scripts/` directories
**Expected outcome**: FAIL (bandit AND pip-audit)

## What this tests

- Bandit scans multiple directories (`src/,scripts/`) in one run
- B602 in `src/` triggers at HIGH threshold
- pip-audit detects fixable CVEs in pinned vulnerable versions
- Both tools report issues simultaneously

## Intentional issues

| File | Issue | Severity |
|------|-------|---------|
| `src/processor.py` | B602: `subprocess.call(shell=True)` | HIGH |
| `scripts/run.py` | B105: hardcoded password | MEDIUM |
| `requirements.txt` | `requests==2.25.0` — CVE-2023-32681 | fixable |
| `requirements.txt` | `Pillow==9.0.0` — multiple CVEs | fixable |
