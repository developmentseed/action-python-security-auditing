"""YAML parser — intentionally insecure for bandit testing."""
import yaml


def parse_config(data: str) -> dict:
    """Parse YAML config string."""
    # B506: yaml.load without Loader — MEDIUM severity
    return yaml.load(data)  # noqa: S506
