# CLAUDE.md — python-security-auditing

## What This Project Is

A **GitHub Action** that runs **bandit** (static code analysis) and **pip-audit** (dependency vulnerability scanning) on Python repos, then consolidates results into a single PR comment, workflow step summary, and downloadable artifact.

It is a composite action (`action.yml`) backed by a small Python package (`src/python_security_auditing/`).

## Architecture

```
action.yml                  ← GitHub Action entry point (composite steps)
src/python_security_auditing/
  __main__.py               ← Orchestrator: settings → runners → report → comment → exit
  settings.py               ← Pydantic-based config from env vars (GitHub Action inputs)
  runners.py                ← Tool invocation: SARIF parsing, pip-audit, package manager adapters
  report.py                 ← Markdown report builder and threshold checker
  pr_comment.py             ← Upsert PR comment via `gh` CLI
```

**Flow:** `Settings` loads env vars → `runners` invokes tools and parses output → `report` builds markdown and checks thresholds → `pr_comment` posts/updates the PR comment → `__main__` exits 0 or 1.

**Key boundaries:**
- `settings.py` — input/config boundary (reads env vars, validates via Pydantic)
- `runners.py` — external tool boundary (subprocess calls to bandit SARIF, pip-audit, package managers)
- `report.py` — pure logic (markdown generation, threshold checking — no I/O except step summary)
- `pr_comment.py` — GitHub API boundary (subprocess calls to `gh` CLI)

## Build & Dev

- **Build system:** Hatch (`hatchling`)
- **Python:** ≥ 3.13
- **Dependencies:** `pydantic-settings`, `pip-audit`, `bandit[sarif]`
- **Dev deps:** `pytest`, `pytest-mock`, `mypy` (strict), `ruff`

### Common Commands

```bash
# Install in dev mode
uv pip install -e ".[dev]"

# Run tests
uv run pytest

# Type checking (strict mode)
uv run mypy src/

# Lint and format
uv run ruff check src/ tests/
uv run ruff format src/ tests/
```

## Testing Conventions

- Tests live in `tests/` and mirror module names: `test_settings.py`, `test_runners.py`, `test_report.py`.
- Test fixtures (JSON/SARIF samples) are in `tests/fixtures/`.
- External tool calls (`subprocess.run`) are mocked in tests — never invoke real `bandit`, `pip-audit`, or `gh` in unit tests.
- Settings are configured via `monkeypatch.setenv()` since `Settings` reads from env vars.
- Run the full suite after any change: `pytest`.

## Code Style

- **Formatter/linter:** Ruff (line-length 100, rules: E, F, I, UP)
- **Type checking:** mypy strict mode
- **Imports:** `from __future__ import annotations` in every module
- **Type annotations:** use `dict[str, Any]`, `list[...]`, `int | None` (modern syntax, no `Optional`/`Dict`/`List`)
- Match existing patterns — don't refactor surrounding code when making a change.

## Key Design Decisions

- **Bandit runs in-process:** `run_bandit()` runs bandit from the package's own environment, writes `results.sarif` at the workspace root (artifact and Code Scanning upload), and reads it back. It fails closed: a crash, a skipped file or no file scanned raises `AuditError`.
- **PR comment is idempotent:** Uses a hidden HTML marker (`<!-- security-scan-results -->`) to find and update the same comment on subsequent pushes.
- **Threshold logic:** `check_thresholds()` in `report.py` returns a boolean; the orchestrator translates that to `sys.exit(1)`.
- **Package manager adapters:** `generate_requirements()` normalizes all package managers to a `requirements.txt` file before passing to `pip-audit`.
