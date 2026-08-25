"""Protected, redacted Windows evidence for a diagnostic canary."""

from __future__ import annotations

import json
import os
import stat
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Final

from .acl import PyWin32AclAdapter
from .completion_proof import CompletionProofError, read_completion_proofs


CANARY_STATUS_FILENAME: Final = "canary-status.json"
CANARY_STATUS_SCHEMA: Final = "endpoint_windows_canary_status_v1"
CANARY_CAPABILITY: Final = "context.diagnostic.collect"
_TOP_LEVEL_FIELDS: Final = frozenset(
    {"schema_version", "release", "transport", "capability", "completion_proof"}
)
_RELEASE_FIELDS: Final = frozenset({"version", "source_revision"})
_TRANSPORT_FIELDS: Final = frozenset(
    {
        "strict_tls",
        "hostname_valid",
        "redirected",
        "gateway_wss",
        "http_fallback",
        "endpoint_host",
    }
)
_COMPLETION_FIELDS: Final = frozenset(
    {"command_id", "capability", "status", "duration_ms", "result_item_count", "timestamp"}
)


def _protect_status_file(path: Path) -> None:
    """Restore the explicit service DACL lost by os.replace()."""
    PyWin32AclAdapter().protect_machine_data_file(path)


class CanaryStatusError(RuntimeError):
    """The fixed canary-status artifact is unsafe or malformed."""


def _is_reparse(path: Path) -> bool:
    details = path.lstat()
    return path.is_symlink() or bool(
        getattr(details, "st_file_attributes", 0) & 0x400
    )


def _require_data_root(data_root: Path) -> None:
    try:
        details = data_root.lstat()
    except OSError as error:
        raise CanaryStatusError("canary status data root is missing") from error
    if _is_reparse(data_root) or not stat.S_ISDIR(details.st_mode):
        raise CanaryStatusError("canary status data root is unsafe")


def _require_regular_file(path: Path) -> None:
    try:
        details = path.lstat()
    except OSError as error:
        raise CanaryStatusError("canary status is missing") from error
    if _is_reparse(path) or not stat.S_ISREG(details.st_mode):
        raise CanaryStatusError("canary status is unsafe")


def _mapping(value: object, *, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise CanaryStatusError(f"canary status {name} schema is invalid")
    return value


def _release(value: object) -> dict[str, str]:
    release = _mapping(value, name="release")
    if set(release) != _RELEASE_FIELDS:
        raise CanaryStatusError("canary status release schema is invalid")
    version = release.get("version")
    revision = release.get("source_revision")
    if not isinstance(version, str) or not version:
        raise CanaryStatusError("canary status release version is invalid")
    if not isinstance(revision, str) or len(revision) != 40:
        raise CanaryStatusError("canary status release revision is invalid")
    return {"version": version, "source_revision": revision}


def _transport(value: object) -> dict[str, object]:
    transport = _mapping(value, name="transport")
    boolean_fields = _TRANSPORT_FIELDS - {"endpoint_host"}
    if (
        set(transport) != _TRANSPORT_FIELDS
        or not all(isinstance(transport.get(field), bool) for field in boolean_fields)
        or not isinstance(transport.get("endpoint_host"), str)
        or not transport["endpoint_host"]
    ):
        raise CanaryStatusError("canary status transport schema is invalid")
    return {
        **{field: bool(transport[field]) for field in boolean_fields},
        "endpoint_host": str(transport["endpoint_host"]),
    }


def _completion(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    completion = _mapping(value, name="completion")
    if set(completion) != _COMPLETION_FIELDS:
        raise CanaryStatusError("canary status completion schema is invalid")
    if not all(isinstance(completion.get(field), str) for field in ("command_id", "capability", "status", "timestamp")):
        raise CanaryStatusError("canary status completion identity is invalid")
    if not all(
        isinstance(completion.get(field), int) and completion[field] >= 0
        for field in ("duration_ms", "result_item_count")
    ):
        raise CanaryStatusError("canary status completion counts are invalid")
    return dict(completion)


def _validated_status(value: object) -> dict[str, object]:
    status = _mapping(value, name="top-level")
    if set(status) != _TOP_LEVEL_FIELDS:
        raise CanaryStatusError("canary status schema is invalid")
    if status.get("schema_version") != CANARY_STATUS_SCHEMA:
        raise CanaryStatusError("canary status schema is invalid")
    if status.get("capability") != CANARY_CAPABILITY:
        raise CanaryStatusError("canary status capability is invalid")
    return {
        "schema_version": CANARY_STATUS_SCHEMA,
        "release": _release(status.get("release")),
        "transport": _transport(status.get("transport")),
        "capability": CANARY_CAPABILITY,
        "completion_proof": _completion(status.get("completion_proof")),
    }


def read_canary_status(data_root: Path) -> dict[str, object]:
    """Read only a validated fixed-path status projection."""
    _require_data_root(data_root)
    path = data_root / CANARY_STATUS_FILENAME
    _require_regular_file(path)
    try:
        return _validated_status(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CanaryStatusError("canary status cannot be read") from error


class CanaryStatusWriter:
    """Publish atomically replaced, bounded facts from the Windows runtime."""

    def __init__(
        self, data_root: Path, release: Mapping[str, object], endpoint_host: str
    ) -> None:
        _require_data_root(data_root)
        if not isinstance(endpoint_host, str) or not endpoint_host:
            raise CanaryStatusError("canary status endpoint host is invalid")
        self._data_root = data_root
        self._release = _release(release)
        self._endpoint_host = endpoint_host

    def _write(self, status: Mapping[str, object]) -> None:
        _require_data_root(self._data_root)
        value = _validated_status(status)
        target = self._data_root / CANARY_STATUS_FILENAME
        if target.exists():
            _require_regular_file(target)
            existing_completion = read_canary_status(self._data_root)["completion_proof"]
            if value["completion_proof"] is None and existing_completion is not None:
                value["completion_proof"] = existing_completion
        temporary = self._data_root / f".{CANARY_STATUS_FILENAME}.{uuid.uuid4().hex}.tmp"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
            _protect_status_file(target)
        except BaseException:
            try:
                temporary.unlink()
            except OSError:
                pass
            raise

    def _existing_completion(self) -> dict[str, object] | None:
        """Keep a bounded terminal marker across a transient reconnect."""
        target = self._data_root / CANARY_STATUS_FILENAME
        if not target.exists() and not target.is_symlink():
            return None
        return read_canary_status(self._data_root)["completion_proof"]

    def write_transport(
        self,
        *,
        strict_tls: bool,
        hostname_valid: bool,
        redirected: bool,
        gateway_wss: bool,
        http_fallback: bool,
    ) -> None:
        self._write(
            {
                "schema_version": CANARY_STATUS_SCHEMA,
                "release": self._release,
                "transport": {
                    "strict_tls": strict_tls,
                    "hostname_valid": hostname_valid,
                    "redirected": redirected,
                    "gateway_wss": gateway_wss,
                    "http_fallback": http_fallback,
                    "endpoint_host": self._endpoint_host,
                },
                "capability": CANARY_CAPABILITY,
                "completion_proof": self._existing_completion(),
            }
        )

    def write_not_ready(self) -> None:
        """Clear all affirmative transport evidence before and after a disconnect."""
        self.write_transport(
            strict_tls=False,
            hostname_valid=False,
            redirected=False,
            gateway_wss=False,
            http_fallback=False,
        )

    def write_wss_ready(self) -> None:
        """Record one verified WSS connection with fallback disabled."""
        self.write_transport(
            strict_tls=True,
            hostname_valid=True,
            redirected=False,
            gateway_wss=True,
            http_fallback=False,
        )

    def with_completion(self, command_id: str) -> None:
        if not isinstance(command_id, str) or not command_id:
            raise CanaryStatusError("canary completion command id is invalid")
        try:
            matches = [
                record
                for record in read_completion_proofs(self._data_root)
                if record["command_id"] == command_id
                and record["capability"] == CANARY_CAPABILITY
            ]
        except CompletionProofError as error:
            raise CanaryStatusError("canary completion proof is unsafe") from error
        if len(matches) > 1:
            raise CanaryStatusError("canary completion proof is ambiguous")
        status = read_canary_status(self._data_root)
        status["completion_proof"] = matches[0] if matches else None
        self._write(status)


__all__ = [
    "CANARY_CAPABILITY",
    "CANARY_STATUS_FILENAME",
    "CANARY_STATUS_SCHEMA",
    "CanaryStatusError",
    "CanaryStatusWriter",
    "read_canary_status",
]
