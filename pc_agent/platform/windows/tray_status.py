"""Fixed, redacted status projection consumed by the Windows tray companion."""

from __future__ import annotations

import json
import os
import re
import stat
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal

from .acl import PyWin32AclAdapter, WindowsAclError


TRAY_STATUS_FILENAME: Final = "agent-status.json"
TRAY_STATUS_SCHEMA: Final = "endpoint_windows_tray_status_v1"
TRAY_DIRECTORY_NAME: Final = "Tray"
MAX_STATUS_AGE_SECONDS: Final = 120
_FIELDS: Final = frozenset(
    {
        "schema_version",
        "version",
        "agent_state",
        "endpoint_state",
        "update_state",
        "observed_at",
        "reason_code",
    }
)
_SEMVER: Final = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
_REASON_CODE: Final = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_AGENT_STATES: Final = frozenset({"running", "starting", "stopped", "error"})
_ENDPOINT_STATES: Final = frozenset(
    {"connected", "connecting", "disconnected", "unknown"}
)
_UPDATE_STATES: Final = frozenset(
    {"up_to_date", "pending", "applying", "failed", "unknown"}
)

AgentState = Literal["running", "starting", "stopped", "error"]
EndpointState = Literal["connected", "connecting", "disconnected", "unknown"]
UpdateState = Literal["up_to_date", "pending", "applying", "failed", "unknown"]


class TrayStatusError(RuntimeError):
    """The public tray status cannot safely be published or consumed."""


@dataclass(frozen=True, slots=True)
class TrayStatus:
    version: str
    agent_state: AgentState
    endpoint_state: EndpointState
    update_state: UpdateState
    observed_at: datetime
    reason_code: str | None


def tray_status_root(data_root: Path) -> Path:
    """Keep public status beside, never inside, the protected Agent data root."""
    return data_root.parent / TRAY_DIRECTORY_NAME


def _is_reparse(path: Path) -> bool:
    details = path.lstat()
    return path.is_symlink() or bool(
        getattr(details, "st_file_attributes", 0) & 0x400
    )


def _require_directory(path: Path, *, name: str) -> None:
    try:
        details = path.lstat()
    except OSError as error:
        raise TrayStatusError(f"tray status {name} is missing") from error
    if _is_reparse(path):
        raise TrayStatusError(f"tray status {name} is a reparse point")
    if not stat.S_ISDIR(details.st_mode):
        raise TrayStatusError(f"tray status {name} is not a directory")


def _require_regular_file(path: Path) -> None:
    try:
        details = path.lstat()
    except OSError as error:
        raise TrayStatusError("tray status is missing") from error
    if _is_reparse(path):
        raise TrayStatusError("tray status is a reparse point")
    if not stat.S_ISREG(details.st_mode):
        raise TrayStatusError("tray status is not a regular file")


def _validate_payload(value: object) -> TrayStatus:
    if not isinstance(value, Mapping) or set(value) != _FIELDS:
        raise TrayStatusError("tray status schema is invalid")
    version = value.get("version")
    agent_state = value.get("agent_state")
    endpoint_state = value.get("endpoint_state")
    update_state = value.get("update_state")
    observed_at = value.get("observed_at")
    reason_code = value.get("reason_code")
    if value.get("schema_version") != TRAY_STATUS_SCHEMA:
        raise TrayStatusError("tray status schema is invalid")
    if not isinstance(version, str) or not _SEMVER.fullmatch(version):
        raise TrayStatusError("tray status version is invalid")
    if agent_state not in _AGENT_STATES:
        raise TrayStatusError("tray status agent state is invalid")
    if endpoint_state not in _ENDPOINT_STATES:
        raise TrayStatusError("tray status endpoint state is invalid")
    if update_state not in _UPDATE_STATES:
        raise TrayStatusError("tray status update state is invalid")
    if reason_code is not None and (
        not isinstance(reason_code, str) or not _REASON_CODE.fullmatch(reason_code)
    ):
        raise TrayStatusError("tray status reason code is invalid")
    if not isinstance(observed_at, str):
        raise TrayStatusError("tray status observation time is invalid")
    try:
        observed = datetime.fromisoformat(observed_at)
    except ValueError as error:
        raise TrayStatusError("tray status observation time is invalid") from error
    if observed.tzinfo is None:
        raise TrayStatusError("tray status observation time is invalid")
    return TrayStatus(
        version=version,
        agent_state=agent_state,
        endpoint_state=endpoint_state,
        update_state=update_state,
        observed_at=observed.astimezone(UTC),
        reason_code=reason_code,
    )


def read_tray_status(data_root: Path, *, now: datetime) -> TrayStatus:
    """Read a validated fresh public projection without following reparse points."""
    if now.tzinfo is None:
        raise TrayStatusError("tray status current time is invalid")
    _require_directory(data_root, name="data root")
    root = tray_status_root(data_root)
    _require_directory(root, name="directory")
    path = root / TRAY_STATUS_FILENAME
    _require_regular_file(path)
    try:
        status = _validate_payload(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TrayStatusError("tray status cannot be read") from error
    now_utc = now.astimezone(UTC)
    if status.observed_at > now_utc:
        raise TrayStatusError("tray status observation is in the future")
    if (now_utc - status.observed_at).total_seconds() > MAX_STATUS_AGE_SECONDS:
        raise TrayStatusError("tray status observation is stale")
    return status


class TrayStatusWriter:
    """Publish exact, non-sensitive state for an unprivileged tray process."""

    def __init__(
        self,
        data_root: Path,
        version: str,
        *,
        now: Callable[[], datetime] | None = None,
        protect: Callable[[Path], None] | None = None,
        acl: PyWin32AclAdapter | None = None,
    ) -> None:
        if not _SEMVER.fullmatch(version):
            raise TrayStatusError("tray status version is invalid")
        self._data_root = data_root
        self._version = version
        self._now = now or (lambda: datetime.now(UTC))
        self._acl = acl or PyWin32AclAdapter()
        self._protect = protect or self._acl.protect_tray_status_file

    def publish(
        self,
        *,
        agent_state: AgentState,
        endpoint_state: EndpointState,
        update_state: UpdateState,
        reason_code: str | None = None,
    ) -> None:
        now = self._now()
        if now.tzinfo is None:
            raise TrayStatusError("tray status observation time is invalid")
        payload = {
            "schema_version": TRAY_STATUS_SCHEMA,
            "version": self._version,
            "agent_state": agent_state,
            "endpoint_state": endpoint_state,
            "update_state": update_state,
            "observed_at": now.astimezone(UTC).isoformat(),
            "reason_code": reason_code,
        }
        _validate_payload(payload)
        _require_directory(self._data_root, name="data root")
        root = tray_status_root(self._data_root)
        self._prepare_root(root)
        target = root / TRAY_STATUS_FILENAME
        if target.exists() or target.is_symlink():
            _require_regular_file(target)
        temporary = root / f".{TRAY_STATUS_FILENAME}.{uuid.uuid4().hex}.tmp"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(
                    json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
                        "utf-8"
                    )
                )
                stream.flush()
                os.fsync(stream.fileno())
            _require_directory(root, name="directory")
            if target.exists() or target.is_symlink():
                _require_regular_file(target)
            os.replace(temporary, target)
            _require_regular_file(target)
            self._protect(target)
        except (OSError, WindowsAclError) as error:
            try:
                temporary.unlink()
            except OSError:
                pass
            raise TrayStatusError("tray status cannot be published") from error

    def _prepare_root(self, root: Path) -> None:
        try:
            if root.exists() or root.is_symlink():
                _require_directory(root, name="directory")
            else:
                root.mkdir()
                _require_directory(root, name="directory")
            self._acl.protect_tray_status_directory(root)
            _require_directory(root, name="directory")
        except (OSError, WindowsAclError) as error:
            raise TrayStatusError("tray status directory cannot be prepared") from error


__all__ = [
    "MAX_STATUS_AGE_SECONDS",
    "TRAY_STATUS_FILENAME",
    "TRAY_STATUS_SCHEMA",
    "TrayStatus",
    "TrayStatusError",
    "TrayStatusWriter",
    "read_tray_status",
    "tray_status_root",
]
