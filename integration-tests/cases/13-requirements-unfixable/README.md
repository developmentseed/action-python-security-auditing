# 13 · requirements · flat · unfixable vulns (should pass)

**Package manager**: `requirements`
**Source layout**: flat
**Expected outcome**: PASS — vulnerabilities exist but have no fix versions; `pip_audit_block_on: fixable` should not block

## What this tests
- `pip_audit_block_on: fixable` only blocks when fix versions are available
- Unfixable vulnerabilities are reported but don't fail the workflow

## Intentional issues

| Package | Version | CVE | Fix Available |
|---------|---------|-----|---------------|
| pygments | 2.19.2 | GHSA-5239-wwwm-4pmq (CVE-2026-4539) | No — Patched versions: None |

ReDoS in `AdlLexer` (archetype.py) via inefficient GUID regex. Low severity. Affects all
versions `<= 2.19.2`. No patched release as of March 2026.
