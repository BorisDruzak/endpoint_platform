"""Argon2id-only administrator password hashing."""

from __future__ import annotations

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError


_PASSWORD_HASHER = PasswordHasher(type=Type.ID)


def hash_password(password: str) -> str:
    """Return an Argon2id digest for a non-empty password."""
    if not password:
        raise ValueError("password must not be empty")
    return _PASSWORD_HASHER.hash(password)


def verify_password(digest: str, password: str) -> bool:
    """Verify a password, rejecting malformed or non-Argon2id digests."""
    if not digest.startswith("$argon2id$") or not password:
        return False
    try:
        return _PASSWORD_HASHER.verify(digest, password)
    except (InvalidHashError, VerificationError, VerifyMismatchError):
        return False
