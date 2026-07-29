"""Shared persistence boundary for public update prose."""

from __future__ import annotations

import re


_SAFE_PROSE_PUNCTUATION = frozenset(" .,:;()!?&#+%'-–—")
_OPAQUE_32_BYTE_SECRET = re.compile(
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])"
)
_DIAGNOSTIC_MARKER = re.compile(
    r"(?i)(?:"
    r"\b(?:token|secret|bearer|authorization|password|cookie|logs?|trace|traceback|"
    r"stacktrace|pending|archive|stdout|stderr)\b|"
    r"\baccess(?:[ ._-]+)token\b|\blog(?:[ ._-]+)output\b|"
    r"\bstack(?:[ ._-]+)trace\b|\bpending(?:[ ._-]+)update\b|"
    r"\.(?:zip|tar\.gz|tgz|7z)\b)"
)


def validate_public_update_prose(
    value: str | None,
    *,
    field_name: str,
    max_length: int,
    required: bool = False,
    allow_newlines: bool = False,
) -> str | None:
    """Return public-safe prose or reject credential/diagnostic-shaped text."""
    if value is None:
        if required:
            raise ValueError(f"a bounded safe {field_name} is required")
        return None
    allowed_punctuation = (
        _SAFE_PROSE_PUNCTUATION | frozenset({"\n"})
        if allow_newlines
        else _SAFE_PROSE_PUNCTUATION
    )
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > max_length
        or any(
            not character.isalnum() and character not in allowed_punctuation
            for character in value
        )
        or _OPAQUE_32_BYTE_SECRET.search(value)
        or _DIAGNOSTIC_MARKER.search(value)
    ):
        raise ValueError(f"{field_name} must be bounded safe public prose")
    return value


__all__ = ["validate_public_update_prose"]
