"""Command runner — intentionally insecure for bandit testing."""
import subprocess


def run_command(cmd: str) -> int:
    """Run a shell command."""
    # B602: subprocess call with shell=True — HIGH severity
    return subprocess.call(cmd, shell=True)  # noqa: S602


def get_config() -> dict:
    """Return config dict."""
    # B105: hardcoded password string — MEDIUM severity
    password = "supersecret123"  # noqa: S105
    return {"password": password}
