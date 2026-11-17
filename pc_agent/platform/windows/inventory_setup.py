"""Private Windows Setup handoff for staging inventory assignments."""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from pc_agent.platform.windows.acl import PyWin32AclAdapter
from pc_agent.platform.windows.durable_state import _checked_path, _copy_identity, _pinned_copy_source


STAGING_ORIGIN = "https://endpoint-staging.sosnadmin.local"
INVENTORY_PREFIX = "inventory-"
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_ID = re.compile(rf"{INVENTORY_PREFIX}({_UUID})-({_UUID})-[0-9a-f]{{32}}")
_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}")
_HANDOFF_SCHEMA = "endpoint_windows_inventory_assignment_v1"
_HANDOFF_LIMIT = 2048
_MINIMUM_NATIVE_CLAIM_WINDOW = timedelta(minutes=10)


def valid_installation_id(value: object) -> bool:
    match = _ID.fullmatch(value) if isinstance(value, str) else None
    return bool(match and all(UUID(part).int for part in match.groups()))


def valid_fingerprint(value: object) -> bool:
    return isinstance(value, str) and bool(_FINGERPRINT.fullmatch(value))


def require_native_claim_window(expires_at: object, now: datetime) -> datetime:
    if not isinstance(expires_at, str):
        raise ValueError("inventory claim expiration is missing")
    deadline = datetime.fromisoformat(expires_at)
    if deadline.tzinfo is None or deadline.astimezone(UTC) - now < _MINIMUM_NATIVE_CLAIM_WINDOW:
        raise ValueError("inventory claim window is too short")
    return deadline.astimezone(UTC)


def read_assignment(path: Path) -> tuple[str, str]:
    if not path.is_absolute() or path.drive.startswith("\\\\"):
        raise ValueError("inventory assignment must be a local absolute file")
    path = _checked_path(path, path.parent)
    with _pinned_copy_source(path) as descriptor:
        identity = _copy_identity(os.fstat(descriptor))
        if _copy_identity(path.lstat()) != identity:
            raise ValueError("inventory assignment identity changed")
        PyWin32AclAdapter().assert_inventory_assignment_file(path)
        if _copy_identity(path.lstat()) != identity or identity[2] > _HANDOFF_LIMIT:
            raise ValueError("inventory assignment file changed or is too large")
        raw = os.read(descriptor, _HANDOFF_LIMIT + 1)
        if len(raw) != identity[2]:
            raise ValueError("inventory assignment file size changed")
        payload = json.loads(raw)
    if (
        not isinstance(payload, dict)
        or payload.keys() != {"schema_version", "installation_id", "hardware_fingerprint"}
        or payload["schema_version"] != _HANDOFF_SCHEMA
        or not valid_installation_id(payload["installation_id"])
        or not valid_fingerprint(payload["hardware_fingerprint"])
    ):
        raise ValueError("invalid Windows inventory assignment")
    return payload["installation_id"], payload["hardware_fingerprint"]
