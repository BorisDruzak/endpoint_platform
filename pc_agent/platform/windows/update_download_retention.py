"""Retire exact Windows Core downloads after durable terminal outcomes."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat

from .acl import WindowsAclError
from .disk_readiness import MAX_ARTIFACT_BYTES
from .durable_state import _checked_path, durable_unlink
from .update_paths import WindowsUpdatePaths


def retire_update_download(paths: WindowsUpdatePaths, pending: dict, *, assert_security=None) -> None:
    """Delete one authenticated operation cache leaf under the update mutex."""
    version, operation = pending.get("version"), pending.get("operation_id")
    digest, size = pending.get("sha256"), pending.get("size")
    if (
        not isinstance(version, str) or not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+-]{0,127}", version)
        or not isinstance(operation, str)
        or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", operation)
        or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
        or type(size) is not int or not 0 < size <= MAX_ARTIFACT_BYTES
    ):
        return
    artifact = paths.downloads_root / f"build-{version}-{operation}.zip"
    if not isinstance(pending.get("artifact_path"), str) or Path(pending["artifact_path"]) != artifact:
        return
    try:
        _checked_path(artifact, paths.updates_root)
        details = artifact.lstat()
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1 or details.st_size != size:
            return
        if assert_security is not None:
            assert_security(artifact)
        with artifact.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if not os.path.samestat(details, opened) or opened.st_size != size:
                return
            actual = hashlib.sha256()
            remaining = size
            while remaining:
                chunk = stream.read(min(remaining, 1024 * 1024))
                if not chunk:
                    return
                actual.update(chunk)
                remaining -= len(chunk)
            if stream.read(1) or actual.hexdigest() != digest:
                return
        observed = artifact.lstat()
        if (
            not os.path.samestat(details, observed)
            or observed.st_size != size
            or observed.st_mtime_ns != details.st_mtime_ns
            or observed.st_ctime_ns != details.st_ctime_ns
        ):
            return
        durable_unlink(artifact, trusted_root=paths.updates_root)
    except (OSError, ValueError, WindowsAclError):
        # Cache cleanup cannot change an already durable terminal result.
        return
