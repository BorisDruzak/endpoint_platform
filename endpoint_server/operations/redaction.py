"""Central fail-safe sanitization for agent-controlled public diagnostic text."""

from __future__ import annotations

import re


_PUBLIC_REDACTION = "[REDACTED]"
_CANONICAL_AGENT_REDACTION = re.compile(r"(?i)<\s*redacted\s*>")
_CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")
_LOG_CONTROL_CHARACTER = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:password|passphrase|token|secret|"
    r"access[_ -]?(?:key|token)|api[_ -]?key|client[_ -]?secret|"
    r"private[_ -]?key|cookie|credential|authorization)"
    r"\s*(?:[:=]|\s+)\s*\S+"
)
_TOKEN_PREFIX = re.compile(r"(?i)(?:tok|token|secret|api|sk|pk)_[A-Za-z0-9_-]{8,}")
_ABSOLUTE_PATH = re.compile(
    r"(?<![A-Za-z0-9_])(?:[A-Za-z]:[\\/][^\s,;]+|"
    r"\\\\[^\s,;]+|/[^\s,;]+)"
)
_TRACEBACK = re.compile(r"(?i)traceback\s*\(\s*most\s+recent\s+call\s+last\s*\)\s*:")
_PYTHON_FILE_LINE = re.compile(r"(?i)file\s+[\"'][^\r\n\"']+[\"']\s*,\s*line\s+\d+")
_BEARER = re.compile(r"(?i)\bbearer\s+\S+")
_SAFE_BEARER = re.compile(
    r"(?i)\bbearer\s+(?:(?:auth|authentication)\s+(?:was\s+)?"
    r"(?:\[redacted\]|redacted|absent|none|null)|"
    r"(?:\[redacted\]|redacted|absent|none|null))(?:[.,;)]?(?:\s|$))"
)


def _contains_unsafe_bearer(value: str) -> bool:
    return any(
        _SAFE_BEARER.match(value, match.start()) is None
        for match in _BEARER.finditer(value)
    )


def sanitize_agent_public_text(
    value: str,
    *,
    limit: int,
    allow_multiline: bool = False,
) -> tuple[str, bool]:
    """Return bounded public text or one opaque marker for sensitive content."""
    control_pattern = _LOG_CONTROL_CHARACTER if allow_multiline else _CONTROL_CHARACTER
    unsafe = (
        _CANONICAL_AGENT_REDACTION.search(value) is not None
        or control_pattern.search(value) is not None
        or _CREDENTIAL_ASSIGNMENT.search(value) is not None
        or _TOKEN_PREFIX.search(value) is not None
        or _ABSOLUTE_PATH.search(value) is not None
        or _TRACEBACK.search(value) is not None
        or _PYTHON_FILE_LINE.search(value) is not None
        or _contains_unsafe_bearer(value)
    )
    if unsafe:
        return _PUBLIC_REDACTION, True
    if len(value) > limit:
        return value[:limit], True
    return value, False


__all__ = ["sanitize_agent_public_text"]
