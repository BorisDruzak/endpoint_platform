"""Local filesystem facts without arbitrary paths or file reads."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
import os
from pathlib import Path
import re
import stat

import psutil

from endpoint_contracts.filesystem_primitives import (
    FileMetadataParametersV1,
    FileMetadataResultV1,
    FreeSpaceParametersV1,
    FreeSpaceResultV1,
    PathExistsParametersV1,
    PathExistsResultV1,
    VolumeFactV1,
)


def _system_root() -> Path:
    return Path(os.path.abspath(os.sep))


def _fixed_path(key: str) -> Path:
    if os.name == "nt":
        program_files = os.environ.get("ProgramW6432") or os.environ.get("ProgramFiles")
        program_data = os.environ.get("ProgramData")
        if not program_files or not program_data:
            raise OSError("Endpoint Windows locations are unavailable")
        install = Path(program_files) / "Endpoint Platform" / "Agent"
        data = Path(program_data) / "Endpoint Platform" / "Agent"
    else:
        install = Path("/opt/endpoint-agent")
        data = Path("/var/lib/endpoint-agent")
    catalog = {
        "endpoint_install_root": install,
        "endpoint_data_root": data,
        "endpoint_runtime_manifest": install / "current.json",
    }
    try:
        return catalog[key]
    except KeyError as error:
        raise ValueError("logical path key is unsupported") from error


def _guard_no_redirect(path: Path) -> None:
    current = path
    while True:
        if current.is_symlink() or current.is_junction():
            raise OSError("logical path crosses a redirect")
        parent = current.parent
        if parent == current:
            return
        current = parent


def free_space(parameters: FreeSpaceParametersV1) -> FreeSpaceResultV1:
    del parameters
    now = datetime.now(UTC)
    try:
        root = _system_root()
        parts = psutil.disk_partitions(all=False)
        matching = next((part for part in parts if os.path.normcase(part.mountpoint.rstrip("\\/")) == os.path.normcase(str(root).rstrip("\\/"))), None)
        if matching is None:
            raise OSError("system volume locality is unknown")
        if "remote" in matching.opts.casefold() or matching.device.startswith(("\\\\", "//")) or matching.fstype.casefold() in {"nfs", "cifs", "smbfs", "sshfs"}:
            raise OSError("system volume is network-backed")
        usage = psutil.disk_usage(str(root))
        fstype = matching.fstype if matching and matching.fstype else "unknown"
        fstype = re.sub(r"[^A-Za-z0-9._-]", "", fstype)[:32] or "unknown"
        return FreeSpaceResultV1(
            schema_version="filesystem_free_space_result_v1",
            volumes=[VolumeFactV1(volume_key="system", filesystem_type=fstype, total_bytes=int(usage.total), free_bytes=int(usage.free))],
            status="succeeded", collected_at=now,
        )
    except (OSError, ValueError, psutil.Error):
        return FreeSpaceResultV1(
            schema_version="filesystem_free_space_result_v1",
            status="failed", error_code="free_space_failed", collected_at=now,
        )


def path_exists(
    parameters: PathExistsParametersV1,
    *, resolve_path: Callable[[str], Path] = _fixed_path,
) -> PathExistsResultV1:
    now = datetime.now(UTC)
    try:
        path = resolve_path(parameters.path_key)
        _guard_no_redirect(path)
        try:
            mode = path.stat(follow_symlinks=False).st_mode
        except FileNotFoundError:
            kind = "missing"
        else:
            kind = "file" if stat.S_ISREG(mode) else "directory" if stat.S_ISDIR(mode) else "other"
        return PathExistsResultV1(
            schema_version="filesystem_path_exists_result_v1",
            path_key=parameters.path_key, exists=kind != "missing", kind=kind,
            status="succeeded", collected_at=now,
        )
    except (OSError, ValueError):
        return PathExistsResultV1(
            schema_version="filesystem_path_exists_result_v1",
            path_key=parameters.path_key, exists=False, kind="missing",
            status="failed", error_code="logical_path_failed", collected_at=now,
        )


def file_metadata(
    parameters: FileMetadataParametersV1,
    *, resolve_path: Callable[[str], Path] = _fixed_path,
) -> FileMetadataResultV1:
    now = datetime.now(UTC)
    try:
        path = resolve_path(parameters.path_key)
        _guard_no_redirect(path)
        try:
            facts = path.stat(follow_symlinks=False)
        except FileNotFoundError:
            return FileMetadataResultV1(
                schema_version="filesystem_file_metadata_result_v1",
                path_key=parameters.path_key, exists=False,
                status="succeeded", collected_at=now,
            )
        if not stat.S_ISREG(facts.st_mode):
            raise OSError("logical metadata target is not a file")
        return FileMetadataResultV1(
            schema_version="filesystem_file_metadata_result_v1",
            path_key=parameters.path_key, exists=True,
            size=max(0, int(facts.st_size)),
            modified_at=datetime.fromtimestamp(facts.st_mtime, UTC),
            status="succeeded", collected_at=now,
        )
    except (OSError, ValueError, OverflowError):
        return FileMetadataResultV1(
            schema_version="filesystem_file_metadata_result_v1",
            path_key=parameters.path_key, exists=False,
            status="failed", error_code="logical_metadata_failed", collected_at=now,
        )
