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
        _write_selector_atomic(paths.current_path, candidate)
        return "migrated"
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


__all__ = [
    "TRANSITION_REGISTRY_KEY",
    "migrate_initial_selector",
    "migrate_production_selector",
]
