"""Neutral validation for an enrollment-issued Endpoint device credential."""

from __future__ import annotations

import re
from pathlib import Path


_DEVICE_CREDENTIAL = re.compile(rb"[A-Za-z0-9_-]{43}")


class DeviceCredentialError(ValueError):
    """The durable credential file is unavailable or malformed."""


def read_device_credential(path: Path) -> str:
    """Read one URL-safe 43-byte bearer with an optional platform newline."""
    try:
        raw = Path(path).read_bytes()
    except OSError as error:
        raise DeviceCredentialError("Endpoint device credential is unavailable") from error
    if raw.endswith(b"\r\n"):
        token = raw[:-2]
    elif raw.endswith(b"\n"):
        token = raw[:-1]
    else:
        token = raw
    if raw not in {token, token + b"\n", token + b"\r\n"} or _DEVICE_CREDENTIAL.fullmatch(token) is None:
        raise DeviceCredentialError("Endpoint device credential is invalid")
    return token.decode("ascii")
