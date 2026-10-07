# 09 · pipenv · flat layout · clean

**Package manager**: `pipenv`
**Source layout**: flat (Python files at project root)
**Expected outcome**: PASS

## What this tests

- `pipenv requirements` correctly reads `Pipfile.lock` and exports deps
- Bandit scans the flat project directory
- No bandit issues, no vulnerable deps
- `Pipfile.lock` is **not committed**: CI generates it (`pipenv install`), so the case audits the latest releases
