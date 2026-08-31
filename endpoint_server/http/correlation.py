"""Validation for operation API tracing headers.

Correlation is deliberately transport-only: callers may correlate a response,
but the value must never become authorization or operation/agent state.
"""

from __future__ import annotations

import re


CORRELATION_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_CORRELATION_ID_RE = re.compile(CORRELATION_ID_PATTERN)


def is_operation_api_request(method: str, path: str) -> bool:
    """Return whether a request is one of the four public Operations API routes."""
    segments = path.split("/")
    if len(segments) == 5 and segments[0] == "" and segments[1:3] == ["api", "v1"]:
        if method != "GET" or not segments[4]:
            return False
        if segments[3] in {"operations", "module-operations"}:
            return True
        return segments[3] == "devices" and segments[4] != "network-identities"
    if len(segments) == 6 and segments[:4] == ["", "api", "v1", "devices"]:
        return bool(segments[4]) and (
            (method == "GET" and segments[5] == "capabilities")
            or (
                method == "POST"
                and segments[5] in {"operations", "module-operations"}
            )
        )
    return False


def is_module_api_request(method: str, path: str) -> bool:
    """Return whether a request belongs to the typed Module Platform API."""
    return (method == "GET" and path == "/api/v1/module-capabilities") or (
        method in {"GET", "POST"}
        and (path == "/api/v1/modules" or path.startswith("/api/v1/modules/"))
    )


def is_correlation_api_request(method: str, path: str) -> bool:
    """Return whether a public typed API must validate and echo correlation."""
    return is_operation_api_request(method, path) or is_module_api_request(method, path)


def is_safe_correlation_id(value: str) -> bool:
    """Accept the bounded ASCII grammar documented by the public API only."""
    return _CORRELATION_ID_RE.fullmatch(value) is not None
