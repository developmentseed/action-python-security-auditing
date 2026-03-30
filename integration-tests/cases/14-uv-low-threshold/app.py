"""Intentional B101 — use of assert in non-test code."""

def validate(value: int) -> int:
    assert value > 0, "Value must be positive"
    return value * 2
