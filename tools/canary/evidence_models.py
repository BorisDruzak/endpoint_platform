"""Strict, secret-free JSON evidence helpers for the staging canary."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any


class CanaryEvidenceError(ValueError):
    """Raised when evidence is not a bounded, publish-safe projection."""


_FORBIDDEN_KEY = re.compile(
    r"(?:authorization|bearer|cookie|csrf|credential|password|private[_.-]?key|"
    r"secret|token)",
    re.IGNORECASE,
)
_FORBIDDEN_VALUE = re.compile(
    r"(?:-----BEGIN(?: [A-Z]+)* PRIVATE KEY-----|\bBearer\s+|"
    r"(?:postgres(?:ql)?|https?)://[^\s:@/]+:[^\s@/]+@)",
    re.IGNORECASE,
)


def validate_evidence_payload(
    payload: Mapping[str, Any], *, allowed_keys: frozenset[str]
) -> None:
    """Reject accidental secrets and unexpected top-level evidence fields."""
    unexpected = set(payload) - allowed_keys
    if unexpected:
        raise CanaryEvidenceError(f"unexpected evidence field: {sorted(unexpected)[0]}")
    _validate_value(payload)


def _validate_value(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise CanaryEvidenceError("evidence keys must be strings")
            if _FORBIDDEN_KEY.search(key):
                raise CanaryEvidenceError(f"forbidden evidence field: {key}")
            _validate_value(nested)
        return
    if isinstance(value, list):
        for nested in value:
            _validate_value(nested)
        return
    if isinstance(value, str) and _FORBIDDEN_VALUE.search(value):
        raise CanaryEvidenceError("forbidden secret-like evidence value")
    if value is not None and not isinstance(value, (str, bool, int, float)):
        raise CanaryEvidenceError("evidence values must be JSON primitives")


def write_secure_json(
    path: Path,
    payload: Mapping[str, Any],
    *,
    allowed_keys: frozenset[str],
) -> None:
    """Create, never overwrite, an owner-only evidence file."""
    validate_evidence_payload(payload, allowed_keys=allowed_keys)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    encoded = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
