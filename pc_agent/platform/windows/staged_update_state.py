"""Installer-owned application lifecycle, separate from native MSI fences.

Readers grant no mutation authority. Writers require the existing live installer
checkpoint scope; their caller retains the canonical product mutex and exact
package capability. The journal never contains credentials or arbitrary paths.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from uuid import UUID

from endpoint_contracts.runtime_payload import read_json, version_tuple
from . import durable_state, installer_fence
from .update_paths import WindowsUpdatePaths

_MAX_BYTES = 64 * 1024
_SCHEMA = "endpoint_windows_staged_update_v1"
_HASH = re.compile(r"[0-9a-f]{64}")
_SOURCE = re.compile(r"[0-9a-f]{40}")
_TERMINAL = {"accepted", "rolled-back"}
_NEXT = {
    "preparing": {"prepared", "rolled-back", "recovery-required"},
    "prepared": {"switching", "rolled-back", "recovery-required"},
    "switching": {"native-settled", "rolling-back", "recovery-required"},
    "native-settled": {"trial", "rolling-back", "recovery-required"},
    "trial": {"accepted", "rolling-back", "recovery-required"},
    "rolling-back": {"rolled-back", "recovery-required"},
    "recovery-required": {"rolling-back", "native-settled"},
    "accepted": set(), "rolled-back": set(),
}


@dataclass(frozen=True)
class StagedUpdateBinding:
    operation_id: str
    old_release: dict[str, object]
    new_release: dict[str, object]
    selected_before: bytes
    previous_before: bytes | None
    selected_tree_sha256_before: str
    previous_tree_sha256_before: str | None
    candidate_version: str
    candidate_source_revision: str
    candidate_tree_sha256: str


@dataclass(frozen=True)
class StagedUpdateRecord:
    binding: StagedUpdateBinding
    phase: str
    sequence: int
    attempt_id: str | None
    owner: dict[str, object]
    switched_at: datetime | None
    safe_code: str | None


def _invalid():
    raise ValueError("UPDATE_STATE_INVALID")


def _uuid(value):
    try:
        if not isinstance(value, str) or str(UUID(value)) != value:
            _invalid()
    except (ValueError, TypeError, AttributeError):
        _invalid()


def _hash(value):
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        _invalid()


def _selector(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 4096:
        _invalid()
    value = read_json(raw, 4096)
    if not isinstance(value, dict):
        _invalid()
    # Historical selectors with version only remain genuine before-state.
    if set(value) != {"version"}:
        if (set(value) != {"schema_version", "version", "source_revision"}
                or type(value["schema_version"]) is not int or value["schema_version"] != 1
                or not isinstance(value["source_revision"], str)
                or not _SOURCE.fullmatch(value["source_revision"])):
            _invalid()
    version_tuple(value["version"])
    return value


def _binding_value(binding):
    from .compound_upgrade_plan import _release
    if not isinstance(binding, StagedUpdateBinding):
        _invalid()
    _uuid(binding.operation_id)
    _release(binding.old_release)
    _release(binding.new_release)
    _selector(binding.selected_before)
    _hash(binding.selected_tree_sha256_before)
    _hash(binding.candidate_tree_sha256)
    if binding.previous_before is not None:
        _selector(binding.previous_before)
        _hash(binding.previous_tree_sha256_before)
    elif binding.previous_tree_sha256_before is not None:
        _invalid()
    if (binding.candidate_version != binding.new_release["version"]
            or binding.candidate_source_revision != binding.new_release["source_revision"]
            or version_tuple(binding.new_release["version"]) <= version_tuple(binding.old_release["version"])):
        _invalid()
    value = asdict(binding)
    value["selected_before"] = binding.selected_before.hex()
    value["previous_before"] = binding.previous_before.hex() if binding.previous_before is not None else None
    return value


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _record_value(record):
    from .compound_upgrade_plan import _owner
    binding = _binding_value(record.binding)
    _owner(record.owner)
    if (record.phase not in _NEXT or type(record.sequence) is not int or not 0 <= record.sequence <= 1024
            or (record.safe_code is not None and (not isinstance(record.safe_code, str)
                or not re.fullmatch(r"[a-z][a-z0-9_-]{0,95}", record.safe_code)))):
        _invalid()
    if record.attempt_id is not None:
        _uuid(record.attempt_id)
    if record.phase in {"trial", "accepted"} and record.attempt_id is None:
        _invalid()
    if record.switched_at is not None and (not isinstance(record.switched_at, datetime)
            or record.switched_at.tzinfo is None):
        _invalid()
    if record.phase not in {"preparing", "prepared", "rolled-back", "recovery-required"} and record.switched_at is None:
        _invalid()
    return {"schema_version": _SCHEMA, "binding": binding,
            "binding_sha256": hashlib.sha256(_canonical(binding)).hexdigest(),
            "phase": record.phase, "sequence": record.sequence, "attempt_id": record.attempt_id,
            "owner": record.owner, "switched_at": record.switched_at.isoformat() if record.switched_at else None,
            "safe_code": record.safe_code}


def _path(paths):
    return installer_fence.state_root(paths) / "staged-update.json"


def _decode_record(value):
    if not isinstance(value, dict) or set(value) != {
            "schema_version", "binding", "binding_sha256", "phase", "sequence",
            "attempt_id", "owner", "switched_at", "safe_code"} or value["schema_version"] != _SCHEMA:
        _invalid()
    binding = dict(value["binding"])
    binding["selected_before"] = bytes.fromhex(binding["selected_before"])
    binding["previous_before"] = bytes.fromhex(binding["previous_before"]) if binding["previous_before"] is not None else None
    record = StagedUpdateRecord(StagedUpdateBinding(**binding), value["phase"], value["sequence"],
                                value["attempt_id"], value["owner"],
                                datetime.fromisoformat(value["switched_at"]) if value["switched_at"] is not None else None,
                                value["safe_code"])
    if _record_value(record) != value:
        _invalid()
    return record


def read_staged_update(paths: WindowsUpdatePaths) -> StagedUpdateRecord | None:
    path = _path(paths)
    try:
        path.parent.lstat()
    except FileNotFoundError:
        return None
    try:
        installer_fence.assert_state_security(path.parent)
        try:
            before = path.lstat()
        except FileNotFoundError:
            return None
        installer_fence.assert_state_security(path)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= _MAX_BYTES:
            _invalid()
        with path.open("rb") as source:
            opened = os.fstat(source.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                _invalid()
            value = read_json(source.read(_MAX_BYTES + 1), _MAX_BYTES)
        after = path.lstat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            _invalid()
        return _decode_record(value)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        raise ValueError("UPDATE_STATE_INVALID") from error


def _write(paths, record):
    value = _record_value(record)
    durable_state.installer_mutation_checkpoint(required=True)
    root = _path(paths).parent
    installer_fence.assert_state_security(root)
    durable_state.write_json_atomic(_path(paths), value, trusted_root=root, max_bytes=_MAX_BYTES,
                                    protect=installer_fence.protect_state)
    return record


def begin_staged_update(paths: WindowsUpdatePaths, binding: StagedUpdateBinding,
                        owner: dict[str, object]) -> StagedUpdateRecord:
    record = StagedUpdateRecord(binding, "preparing", 0, None, dict(owner), None, None)
    _record_value(record)
    durable_state.installer_mutation_checkpoint(required=True)
    existing = read_staged_update(paths)
    if existing is not None and existing.phase not in _TERMINAL:
        if existing.binding != binding or existing.owner != owner or existing.phase != "preparing":
            _invalid()
        return existing
    if paths.current_path.read_bytes() != binding.selected_before:
        _invalid()
    previous = paths.previous_path.read_bytes() if paths.previous_path.exists() else None
    if previous != binding.previous_before:
        _invalid()
    if existing is not None:
        from .installation_provenance import _archive_directory
        history = _archive_directory(_path(paths).parent, 'staged-history')
        leaf = history / (existing.binding.operation_id + '.json')
        raw = _path(paths).read_bytes()
        if leaf.exists():
            if read_archived_staged_update(paths, existing.binding.operation_id) != existing or leaf.read_bytes() != raw:
                _invalid()
        else:
            durable_state.write_bytes_atomic(leaf, raw, trusted_root=history, max_bytes=_MAX_BYTES,
                                            protect=installer_fence.protect_state)
    return _write(paths, record)


def advance_staged_update(paths, operation_id: str, expected_phase: str, next_phase: str, *,
                          attempt_id: str | None = None, safe_code: str | None = None) -> StagedUpdateRecord:
    durable_state.installer_mutation_checkpoint(required=True)
    record = read_staged_update(paths)
    if (record is None or record.binding.operation_id != operation_id or record.phase != expected_phase
            or next_phase not in _NEXT[record.phase] or (attempt_id is not None and next_phase != "trial")):
        _invalid()
    return _write(paths, replace(record, phase=next_phase, sequence=record.sequence + 1,
                                attempt_id=attempt_id or record.attempt_id,
                                switched_at=datetime.now(UTC) if next_phase == "switching" else record.switched_at,
                                safe_code=safe_code))


def assert_staged_update_allowed(paths, *, purpose: str, runtime_tree_sha256: str | None = None) -> None:
    from .update_transaction import UpdateInProgress
    if purpose not in {"launch", "ota", "setup", "cleanup"}:
        _invalid()
    record = read_staged_update(paths)
    if record is None or record.phase in _TERMINAL:
        return
    binding = record.binding
    if purpose == "launch":
        if record.phase in {"preparing", "prepared"}:
            if (runtime_tree_sha256 == binding.selected_tree_sha256_before
                    and paths.current_path.read_bytes() == binding.selected_before):
                return
        elif record.phase == "trial":
            if (runtime_tree_sha256 == binding.candidate_tree_sha256
                    and _selector(paths.current_path.read_bytes()) == {
                        "schema_version": 1, "version": binding.candidate_version,
                        "source_revision": binding.candidate_source_revision}):
                return
    raise UpdateInProgress("STAGED_UPDATE_IN_PROGRESS")


def read_archived_staged_update(paths, operation_id):
    _uuid(operation_id)
    path = _path(paths).parent / 'staged-history' / (operation_id + '.json')
    installer_fence.assert_state_security(path)
    from .installation_provenance import _read
    record = _decode_record(read_json(_read(path, _MAX_BYTES), _MAX_BYTES))
    if record.binding.operation_id != operation_id or record.phase not in _TERMINAL:
        _invalid()
    return record
