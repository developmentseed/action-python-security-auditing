"""Request handler — intentionally insecure for bandit testing."""
import subprocess


def handle_request(cmd: str) -> int:
    """Execute a request via shell command."""
    # B602: subprocess with shell=True — HIGH severity
    return subprocess.call(cmd, shell=True)  # noqa: S602
