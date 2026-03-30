"""Deploy script — intentionally insecure for bandit testing."""
import subprocess


def deploy(target: str) -> None:
    """Deploy to the given target."""
    # B602: subprocess with shell=True — HIGH severity
    subprocess.call(f"deploy.sh {target}", shell=True)  # noqa: S602
