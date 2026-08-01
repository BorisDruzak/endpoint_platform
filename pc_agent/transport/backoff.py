"""Bounded delay calculation for transient Gateway reconnects."""

from __future__ import annotations


def bounded_exponential_backoff(
    attempt: int,
    *,
    base_seconds: float = 1.0,
    maximum_seconds: float = 60.0,
) -> float:
    """Return a deterministic, bounded exponential reconnect delay."""
    if attempt < 0:
        raise ValueError("backoff attempt must not be negative")
    if base_seconds <= 0 or maximum_seconds <= 0:
        raise ValueError("backoff bounds must be positive")
    if base_seconds > maximum_seconds:
        raise ValueError("backoff base must not exceed the maximum")
    return min(base_seconds * (2**attempt), maximum_seconds)
