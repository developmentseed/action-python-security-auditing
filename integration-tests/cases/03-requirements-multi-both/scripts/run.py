"""Runner script — intentionally insecure for bandit testing."""


def authenticate(user: str) -> dict:
    """Return auth config for a user."""
    # B105: hardcoded password string — MEDIUM severity
    db_password = "hardcoded_db_pass"  # noqa: S105
    return {"user": user, "db_password": db_password}
