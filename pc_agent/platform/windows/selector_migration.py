"""Approved MSI transition of the immutable initial runtime selector."""

from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path

from pc_agent.platform.windows.update_paths import WindowsUpdatePaths


TRANSITION_REGISTRY_KEY = (
    r"Software\Endpoint Platform\Endpoint Agent\InitialRuntimeTransition"
)
_SEMVER = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
_CONTRACT_FIELDS = {"approved", "from_version", "schema_version", "to_version"}
MSI_RUNTIME_MARKER_FILENAME = ".endpoint-msi-runtime.json"
ROLLBACK_SNAPSHOT_FILENAME = ".endpoint-initial-runtime-selector.rollback.json"
_MARKER_FIELDS = {"component_guid", "schema_version", "version"}
_SNAPSHOT_FIELDS = {"schema_version", "version"}


def _read_exact_json(path: Path, fields: set[str], label: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is unreadable") from error
    if not isinstance(payload, dict) or set(payload) != fields:
        raise ValueError(f"{label} is invalid")
    return payload


def _validate_runtime(paths: WindowsUpdatePaths, version: str) -> None:
    from pc_agent.platform.windows.service_launcher import validate_runtime_executable

    validate_runtime_executable(paths, version)


def _write_selector_atomic(path: Path, version: str) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as output:
            output.write(json.dumps({"version": version}, separators=(",", ":")))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _rollback_path(paths: WindowsUpdatePaths) -> Path:
    return paths.install_root / ROLLBACK_SNAPSHOT_FILENAME


def _write_rollback_snapshot(paths: WindowsUpdatePaths, version: str) -> None:
    snapshot = _rollback_path(paths)
    temporary = snapshot.with_name(f".{snapshot.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as output:
            output.write(json.dumps({"schema_version": 1, "version": version}, separators=(",", ":")))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, snapshot)
    finally:
        temporary.unlink(missing_ok=True)


def _is_msi_owned_runtime(paths: WindowsUpdatePaths, version: str) -> bool:
    marker = paths.versions_root / version / MSI_RUNTIME_MARKER_FILENAME
    try:
        details = marker.lstat()
    except FileNotFoundError:
        return False
    if marker.is_symlink() or getattr(details, "st_file_attributes", 0) & 0x400:
        raise ValueError("MSI runtime marker is a reparse point")
    marker_payload = _read_exact_json(marker, _MARKER_FIELDS, "MSI runtime marker")
    component_guid = marker_payload.get("component_guid")
    if (
        marker_payload.get("schema_version") != 1
        or marker_payload.get("version") != version
        or not isinstance(component_guid, str)
    ):
        raise ValueError("MSI runtime marker is invalid")
    try:
        canonical_guid = str(uuid.UUID(component_guid)).upper()
    except ValueError as error:
        raise ValueError("MSI runtime marker is invalid") from error
    if canonical_guid != component_guid:
        raise ValueError("MSI runtime marker is invalid")
    _validate_runtime(paths, version)
    return True


def _migrate_versions(
    paths: WindowsUpdatePaths, previous: object, candidate: object
) -> str:
    if (
        not isinstance(previous, str)
        or not isinstance(candidate, str)
        or not _SEMVER.fullmatch(previous)
        or not _SEMVER.fullmatch(candidate)
        or previous == candidate
    ):
        raise ValueError("transition contract is invalid")
    _validate_runtime(paths, candidate)
    current = _read_exact_json(paths.current_path, {"version"}, "current selector")
    selected = current.get("version")
    if not isinstance(selected, str) or not _SEMVER.fullmatch(selected):
        raise ValueError("current selector is invalid")
    if selected == previous:
        _write_rollback_snapshot(paths, selected)
        _write_selector_atomic(paths.current_path, candidate)
        return "migrated"
    if _is_msi_owned_runtime(paths, selected):
        _write_rollback_snapshot(paths, selected)
        _write_selector_atomic(paths.current_path, candidate)
        return "migrated_msi_owned"
    _validate_runtime(paths, selected)
    return "preserved"


def migrate_initial_selector(
    paths: WindowsUpdatePaths, contract_path: Path
) -> str:
    """Testable file boundary for the approved transition contract."""
    contract = _read_exact_json(contract_path, _CONTRACT_FIELDS, "transition contract")
    if contract.get("schema_version") != 1 or contract.get("approved") is not True:
        raise ValueError("transition contract is invalid")
    return _migrate_versions(
        paths, contract.get("from_version"), contract.get("to_version")
    )


def migrate_production_selector() -> str:
    """Read only MSI-authored fixed HKLM values; accept no caller paths."""
    try:
        import winreg
    except ImportError as error:
        raise RuntimeError("winreg is required for selector migration") from error
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, TRANSITION_REGISTRY_KEY, 0, winreg.KEY_READ
        ) as key:
            approved, _approved_type = winreg.QueryValueEx(key, "Approved")
            previous, _previous_type = winreg.QueryValueEx(key, "FromVersion")
            candidate, _candidate_type = winreg.QueryValueEx(key, "ToVersion")
    except OSError as error:
        raise ValueError("transition registry contract is unreadable") from error
    if approved != 1 or isinstance(approved, bool):
        raise ValueError("transition registry contract is not approved")
    return _migrate_versions(WindowsUpdatePaths.production(), previous, candidate)


def rollback_initial_selector(paths: WindowsUpdatePaths) -> str:
    """Restore the selector snapshot when MSI rolls back after migration."""
    snapshot = _rollback_path(paths)
    try:
        payload = _read_exact_json(snapshot, _SNAPSHOT_FIELDS, "selector rollback snapshot")
    except ValueError as error:
        if not snapshot.exists():
            return "not_migrated"
        raise error
    version = payload.get("version")
    if payload.get("schema_version") != 1 or not isinstance(version, str) or not _SEMVER.fullmatch(version):
        raise ValueError("selector rollback snapshot is invalid")
    _write_selector_atomic(paths.current_path, version)
    snapshot.unlink(missing_ok=True)
    return "restored"


def finalize_initial_selector_migration(paths: WindowsUpdatePaths) -> str:
    """Discard a rollback snapshot only after MSI commits successfully."""
    snapshot = _rollback_path(paths)
    if snapshot.exists():
        snapshot.unlink()
        return "finalized"
    return "not_migrated"


def rollback_production_selector() -> str:
    return rollback_initial_selector(WindowsUpdatePaths.production())


def finalize_production_selector_migration() -> str:
    return finalize_initial_selector_migration(WindowsUpdatePaths.production())


__all__ = [
    "TRANSITION_REGISTRY_KEY",
    "MSI_RUNTIME_MARKER_FILENAME",
    "ROLLBACK_SNAPSHOT_FILENAME",
    "finalize_initial_selector_migration",
    "finalize_production_selector_migration",
    "migrate_initial_selector",
    "migrate_production_selector",
    "rollback_initial_selector",
    "rollback_production_selector",
]
