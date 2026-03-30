"""Auth module — intentionally insecure for bandit testing."""
import hashlib


def legacy_hash(data: bytes) -> str:
    """Compute a legacy hash of data."""
    # B303: use of MD5 — MEDIUM severity
    return hashlib.md5(data).hexdigest()  # noqa: S324


def check_token(token: str) -> bool:
    """Validate an API token."""
    # B105: hardcoded password string — MEDIUM severity
    secret = "dev_secret_token_abc123"  # noqa: S105
    return token == secret
