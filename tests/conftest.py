import pytest


@pytest.fixture(autouse=True)
def _no_github_workspace(monkeypatch: pytest.MonkeyPatch) -> None:
    """CI sets GITHUB_WORKSPACE; tests that need it set it themselves."""
    monkeypatch.delenv("GITHUB_WORKSPACE", raising=False)
