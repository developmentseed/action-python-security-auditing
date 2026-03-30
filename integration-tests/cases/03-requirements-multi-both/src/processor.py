"""Data processor — intentionally insecure for bandit testing."""
import subprocess


def process(data: str) -> None:
    """Process data via shell command."""
    # B602: subprocess with shell=True — HIGH severity
    subprocess.call(f"process.sh {data}", shell=True)  # noqa: S602
