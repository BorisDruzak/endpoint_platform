"""Bounded audit correlation identifiers derived from untrusted HTTP input."""

from __future__ import annotations

import hashlib
import hmac
from uuid import uuid4

from fastapi import Request


_AUDIT_REQUEST_ID_CONTEXT = b"endpoint-audit-request-id-v1\0"


def audit_request_id(request: Request) -> str:
    """Return a non-secret audit identifier without persisting a raw header."""
    if "x-request-id" not in request.headers:
        return f"server_{uuid4().hex}"
    supplied = request.headers["x-request-id"].encode("utf-8")
    digest = hmac.new(
        request.app.state.settings.session_secret,
        _AUDIT_REQUEST_ID_CONTEXT + supplied,
        hashlib.sha256,
    ).hexdigest()
    return f"external_{digest}"
