"""Validation for operation API tracing headers.

Correlation is deliberately transport-only: callers may correlate a response,
but the value must never become authorization or operation/agent state.
"""

from __future__ import annotations

import re


CORRELATION_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_CORRELATION_ID_RE = re.compile(CORRELATION_ID_PATTERN)


def is_operation_api_path(path: str) -> bool:
    """Return whether a path belongs to the public Operations API v1 contract."""
    return path.startswith("/api/v1/devices/") or path.startswith("/api/v1/operations/")


def is_safe_correlation_id(value: str) -> bool:
    """Accept the bounded ASCII grammar documented by the public API only."""
    return _CORRELATION_ID_RE.fullmatch(value) is not None
