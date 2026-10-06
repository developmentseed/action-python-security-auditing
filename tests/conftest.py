import os

import pytest
from python_security_auditing.settings import Settings

# Settings reads these case-insensitively; runners.py also reads PIPENV_PIPFILE.
_READ_FROM_ENV = {*Settings.model_fields, "pipenv_pipfile"}


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """CI sets GITHUB_STEP_SUMMARY, GITHUB_WORKSPACE, RUNNER_DEBUG...: tests set what they need."""
    for name in list(os.environ):
        if name.lower() in _READ_FROM_ENV:
            monkeypatch.delenv(name)
