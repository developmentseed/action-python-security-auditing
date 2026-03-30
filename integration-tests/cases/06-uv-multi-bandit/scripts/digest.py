"""Digest utility — intentionally insecure for bandit testing."""
import hashlib


def compute_hash(data: bytes) -> str:
    """Compute a digest of the given data."""
    # B303: use of MD5 — MEDIUM severity
    return hashlib.md5(data).hexdigest()  # noqa: S324
