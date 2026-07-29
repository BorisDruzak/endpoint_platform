"""Recursive, fail-closed redaction for persisted audit details."""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from datetime import date, datetime, time
from decimal import Decimal
from enum import Enum
from pathlib import PurePath
from typing import TypeAlias
from uuid import UUID


REDACTED = "[REDACTED]"
_SENSITIVE_KEY_PARTS = (
    "password",
    "token",
    "authorization",
    "cookie",
    "secret",
    "bearer",
)
_SENSITIVE_EXACT_KEYS = frozenset({"campaign", "claim", "receipt"})
_BEARER_VALUE = re.compile(r"(?i)\bbearer\s+[^\s,;]+")
_NON_ALPHANUMERIC = re.compile(r"[^a-z0-9]+")

JSONScalar: TypeAlias = None | bool | int | float | str
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]


def _redact_bearer_values(value: str) -> str:
    return _BEARER_VALUE.sub(f"Bearer {REDACTED}", value)


def _is_sensitive_key(key: str) -> bool:
    normalized = _NON_ALPHANUMERIC.sub("", key.casefold())
    return normalized in _SENSITIVE_EXACT_KEYS or any(
        part in normalized for part in _SENSITIVE_KEY_PARTS
    )


def _json_key(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (int, UUID, PurePath)):
        return str(value)
    raise TypeError("audit detail mapping keys must be JSON-safe strings")


def _redact(value: object, active_containers: set[int]) -> JSONValue:
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("audit detail numbers must be finite")
        return value
    if isinstance(value, str):
        return _redact_bearer_values(value)
    if isinstance(value, Enum):
        return _redact(value.value, active_containers)
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, (UUID, PurePath, Decimal)):
        return str(value)

    if isinstance(value, Mapping):
        identity = id(value)
        if identity in active_containers:
            raise ValueError("circular audit details are not supported")
        active_containers.add(identity)
        try:
            result: dict[str, JSONValue] = {}
            for raw_key, child in value.items():
                key = _json_key(raw_key)
                result[key] = (
                    REDACTED
                    if _is_sensitive_key(key)
                    else _redact(child, active_containers)
                )
            return result
        finally:
            active_containers.remove(identity)

    if isinstance(value, (list, tuple)):
        identity = id(value)
        if identity in active_containers:
            raise ValueError("circular audit details are not supported")
        active_containers.add(identity)
        try:
            return [_redact(child, active_containers) for child in value]
        finally:
            active_containers.remove(identity)

    raise TypeError(
        f"audit detail value of type {type(value).__name__} is not JSON-safe"
    )


def redact_audit_details(details: object) -> JSONValue:
    """Return a detached JSON-safe value with credential material removed."""
    return _redact(details, set())
