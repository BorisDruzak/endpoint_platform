"""Closed capability mapping for Endpoint Operation v1."""

from __future__ import annotations


CAPABILITY_PROFILES = {"context.diagnostic.collect": "diagnostic_v1"}
SUPPORTED_CAPABILITIES = frozenset(CAPABILITY_PROFILES)


class UnsupportedOperationCapability(ValueError):
    """The request is outside the closed Endpoint Operation v1 allowlist."""


def profile_for_capability(capability: str) -> str:
    try:
        return CAPABILITY_PROFILES[capability]
    except KeyError as error:
        raise UnsupportedOperationCapability(
            "unsupported endpoint operation capability"
        ) from error


__all__ = [
    "CAPABILITY_PROFILES",
    "SUPPORTED_CAPABILITIES",
    "UnsupportedOperationCapability",
    "profile_for_capability",
]
