"""Bounded, unambiguous JSON and canonical integrity digests."""
import hashlib
import json
from datetime import datetime, timedelta, timezone
from uuid import UUID


def require(condition, message="continuation gate refused"):
    if not condition:
        raise ValueError(message)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(value) -> str:
    return sha256(canonical(value))


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def _constant(_):
    raise ValueError("nonfinite JSON constant")


def parse_json(raw: bytes, limit: int = 8 * 1024 * 1024) -> dict:
    require(type(raw) is bytes and 0 < len(raw) <= limit, "JSON byte bound")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=_constant)
        require(type(value) is dict, "JSON object required")
        canonical(value)  # Reject overflow to infinity, too-deep objects, etc.
        return value
    except (UnicodeError, RecursionError, OverflowError) as error:
        raise ValueError("invalid JSON encoding or depth") from error


def integer(value, low=0, high=2**63 - 1):
    require(type(value) is int and low <= value <= high, "typed integer bound")
    return value


def hex256(value):
    require(type(value) is str and len(value) == 64
            and all(c in "0123456789abcdef" for c in value), "SHA256 format")
    return value


def uuid(value):
    require(type(value) is str and str(UUID(value)) == value, "canonical UUID")
    return value


def instant(value):
    require(type(value) is str, "UTC timestamp required")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.tzinfo is not None and result.utcoffset() == timedelta(0), "UTC required")
    return result.astimezone(timezone.utc)
