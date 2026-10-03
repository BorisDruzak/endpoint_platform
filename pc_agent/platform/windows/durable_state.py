"""Offline durable transitions in an existing, caller-protected state root.

The caller provisions and validates directory ownership/ACLs and serializes
writers. Neither the root nor its ancestors may be writable by untrusted
principals: path checks do not replace that security boundary. Missing parent
directories are deliberately not created with an inherited/default ACL here.
"""
from __future__ import annotations

from collections.abc import Callable
import json
import os
from pathlib import Path
import stat
import uuid

_WINDOWS = os.name == "nt"
_REPARSE_POINT = 0x400


def _reject_reparse(details: os.stat_result) -> None:
    if stat.S_ISLNK(details.st_mode) or getattr(details, "st_file_attributes", 0) & _REPARSE_POINT:
        raise ValueError("state path contains a symlink or reparse point")


def _check_directories(path: Path) -> None:
    for directory in [*reversed(path.parents), path]:
        details = directory.lstat()
        _reject_reparse(details)
        if not stat.S_ISDIR(details.st_mode):
            raise ValueError("state parent is not a directory")


def _checked_path(path: Path, trusted_root: Path) -> Path:
    if ".." in path.parts or ".." in trusted_root.parts:
        raise ValueError("state path escapes trusted root")
    root = trusted_root.absolute()
    destination = path.absolute()
    try:
        relative = destination.relative_to(root)
    except ValueError as error:
        raise ValueError("state path escapes trusted root") from error
    if not relative.parts or any(":" in part for part in relative.parts):
        raise ValueError("state path must be a file within trusted root")
    if _WINDOWS and any(part.endswith((".", " ")) or Path(part).is_reserved() for part in relative.parts):
        raise ValueError("state path contains an unsafe Windows alias")
    _check_directories(destination.parent)
    try:
        details = destination.lstat()
    except FileNotFoundError:
        return destination
    _reject_reparse(details)
    if not stat.S_ISREG(details.st_mode):
        raise ValueError("state destination is not a regular file")
    return destination


def _check_temporary(path: Path, root: Path, identity: os.stat_result) -> None:
    _checked_path(path, root)
    details = path.lstat()
    if (details.st_dev, details.st_ino) != (identity.st_dev, identity.st_ino) or details.st_nlink != 1:
        raise ValueError("unsafe temporary state file identity")


def _remove_temporary(path: Path, root: Path, identity: os.stat_result) -> None:
    # Only clean up the file we created. A collision or substituted path belongs
    # to someone else and must never be followed/deleted, even during failure.
    try:
        _check_temporary(path, root, identity)
    except FileNotFoundError:
        return
    path.unlink()


def write_bytes_atomic(
    path: Path,
    data: bytes,
    *,
    trusted_root: Path,
    max_bytes: int,
    protect: Callable[[Path], None] | None = None,
) -> None:
    """Publish exact bounded bytes after protection and a successful file fsync.

    A directory flush failure is an error even if the new document is already
    visible. Consumers must not treat such an exception as durable success.
    ``protect`` receives the empty exclusive temporary before any bytes exist;
    its ACL is carried into the destination by the same-directory replacement.
    """
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    if not isinstance(data, bytes):
        raise TypeError("state data must be bytes")
    if len(data) > max_bytes:
        raise ValueError("state size exceeds max_bytes")
    destination = _checked_path(path, trusted_root)
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    _checked_path(temporary, trusted_root)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    identity = None
    try:
        try:
            identity = os.fstat(descriptor)
            _check_temporary(temporary, trusted_root, identity)
            if protect is not None:
                protect(temporary)
            _check_temporary(temporary, trusted_root, identity)
            remaining = memoryview(data)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("short write of durable state")
                remaining = remaining[written:]
            # os.write is unbuffered; fsync flushes the complete file, including
            # the protection callback's metadata, before the rename boundary.
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _checked_path(destination, trusted_root)
        _check_temporary(temporary, trusted_root, identity)
        os.replace(temporary, destination)
        flush_directory(destination.parent)
    finally:
        if identity is not None:
            _remove_temporary(temporary, trusted_root, identity)


def write_json_atomic(
    path: Path,
    payload: object,
    *,
    trusted_root: Path,
    max_bytes: int,
    protect: Callable[[Path], None] | None = None,
) -> None:
    """Serialize a JSON document (including journal lists) with a byte bound."""
    data = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
    write_bytes_atomic(path, data, trusted_root=trusted_root, max_bytes=max_bytes, protect=protect)


def durable_unlink(path: Path, *, trusted_root: Path, missing_ok: bool = False) -> None:
    """Delete a regular state leaf and flush its containing directory."""
    destination = _checked_path(path, trusted_root)
    try:
        destination.unlink()
    except FileNotFoundError:
        if not missing_ok:
            raise
    # Retrying an already absent marker must complete a previous failed flush.
    flush_directory(destination.parent)


def flush_directory(path: Path) -> None:
    """Persist metadata; surface native Windows failures as chained OSError."""
    path = path.absolute()
    _check_directories(path)
    if _WINDOWS:
        try:
            import win32con  # type: ignore[import-not-found]
            import win32file  # type: ignore[import-not-found]
            import pywintypes  # type: ignore[import-not-found]
        except ImportError as error:
            raise OSError("pywin32 is required for Windows directory durability") from error
        try:
            handle = win32file.CreateFile(
                str(path),
                win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
                None,
                win32con.OPEN_EXISTING,
                win32con.FILE_FLAG_BACKUP_SEMANTICS | win32file.FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
            try:
                if win32file.GetFileInformationByHandle(handle)[0] & _REPARSE_POINT:
                    raise ValueError("directory handle is a reparse point")
                win32file.FlushFileBuffers(handle)
            finally:
                handle.Close()
        except pywintypes.error as error:
            # Portable callers recover OSError; preserve the native code/cause
            # for diagnosis without mistaking a visible transition for success.
            raise OSError(None, str(error), str(path), error.winerror) from error
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
