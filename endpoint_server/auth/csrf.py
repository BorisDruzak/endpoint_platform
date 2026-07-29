"""Cross-site request forgery protection for administrator sessions."""

from __future__ import annotations

import base64
import hashlib
import hmac

from fastapi import HTTPException, Request, status


CSRF_HEADER = "x-csrf-token"
_CSRF_CONTEXT = b"endpoint-admin-csrf-v1\0"
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


def csrf_token_for_session(session_token: str, session_secret: bytes) -> str:
    """Derive a domain-separated, per-session CSRF token."""
    if not session_token or not session_secret:
        raise ValueError("session token and secret must not be empty")
    digest = hmac.new(
        session_secret,
        _CSRF_CONTEXT + session_token.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def enforce_csrf(
    request: Request, session_token: str, session_secret: bytes
) -> None:
    """Reject unsafe requests without the matching per-session CSRF header."""
    if request.method.upper() in _SAFE_METHODS:
        return
    supplied = request.headers.get(CSRF_HEADER, "")
    expected = csrf_token_for_session(session_token, session_secret)
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF validation failed",
        )
