"""Offline durable transitions in an existing, caller-protected state root.

The caller provisions and validates directory ownership/ACLs and serializes
writers. Neither the root nor its ancestors may be writable by untrusted
principals: path checks do not replace that security boundary. Missing parent
directories are deliberately not created with an inherited/default ACL here.
"""
from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import json
import os
from pathlib import Path
import stat
import re
import uuid

_WINDOWS = os.name == "nt"
_REPARSE_POINT = 0x400
_INSTALLER_CHECKPOINT: ContextVar[Callable[[], None] | None] = ContextVar('installer_checkpoint', default=None)


@contextmanager
def installer_mutation_checkpoints(checkpoint: Callable[[], None]):
    """Add live-owner checks within an already authenticated installer scope.

    This does not grant transaction ownership or bypass the installer fence.
    Ordinary callers retain their existing behavior and import graph.
    """
    if not callable(checkpoint):
        raise TypeError('installer checkpoint must be callable')
    token = _INSTALLER_CHECKPOINT.set(checkpoint)
    try:
        yield
    finally:
        _INSTALLER_CHECKPOINT.reset(token)


def installer_mutation_checkpoint() -> None:
    checkpoint = _INSTALLER_CHECKPOINT.get()
    if checkpoint is not None:
        checkpoint()


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
    # Once the owner is lost, preserve even partial evidence. In particular,
    # cleanup must not turn the original publication failure into a success.
    try:
        installer_mutation_checkpoint()
    except Exception:
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
    installer_mutation_checkpoint()
    descriptor = os.open(temporary, flags, 0o600)
    identity = None
    try:
        try:
            identity = os.fstat(descriptor)
            _check_temporary(temporary, trusted_root, identity)
            if protect is not None:
                protect(temporary)
            _check_temporary(temporary, trusted_root, identity)
            installer_mutation_checkpoint()
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
        installer_mutation_checkpoint()
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


def _copy_identity(details):
    _reject_reparse(details)
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
        raise ValueError('archive source is not a unique regular file')
    # CPython 3.12 Windows lstat aliases ctime to birthtime, whereas fstat
    # exposes native ChangeTime. Compare the explicit creation field across
    # the two APIs, and compare descriptor ChangeTime separately below.
    timestamp = details.st_birthtime_ns if _WINDOWS else details.st_ctime_ns
    return (details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns, timestamp)


@contextmanager
def _pinned_copy_source(path: Path):
    if _WINDOWS:
        import msvcrt
        import win32file
        # Existing writers make this fail. Keep only FILE_SHARE_READ through
        # publication so neither rename/delete nor writing can race the copy.
        handle = win32file.CreateFile(str(path), 0x80000000, 1, None, 3, 0x00200000, None)
        try:
            descriptor = msvcrt.open_osfhandle(handle.Detach(), os.O_RDONLY | os.O_BINARY)
        except BaseException:
            handle.Close()
            raise
    else:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def _verify_copy_bytes(descriptor, expected_size, expected_sha256):
    os.lseek(descriptor, 0, os.SEEK_SET)
    total, digest = 0, hashlib.sha256()
    while block := os.read(descriptor, 1024 * 1024):
        total += len(block)
        if total > expected_size:
            raise ValueError('archive size differs')
        digest.update(block)
    if total != expected_size or digest.hexdigest() != expected_sha256:
        raise ValueError('archive identity differs')


def durable_copy_file(
    source: Path, path: Path, *, source_root: Path, trusted_root: Path,
    max_bytes: int, expected_size: int, expected_sha256: str,
    protect: Callable[[Path], None], validate: Callable[[Path], None],
) -> None:
    """Publish a bounded exact immutable archive using the shared file barrier.

    Caller validates both trusted roots and supplies the archive ACL policy.
    Existing destinations are accepted only as exact resumable copies; unknown
    bytes are never replaced. Source permissions are never copied to archives.
    """
    if (type(max_bytes) is not int or type(expected_size) is not int
        or max_bytes <= 0 or not 0 <= expected_size <= max_bytes or not isinstance(expected_sha256, str)
        or not re.fullmatch(r'[0-9a-f]{64}', expected_sha256) or not callable(protect) or not callable(validate)):
        raise ValueError('archive bounds or identity are invalid')
    source = _checked_path(source, source_root)
    destination = _checked_path(path, trusted_root)
    before = _copy_identity(source.lstat())
    if before[2] != expected_size or source == destination:
        raise ValueError('archive source identity differs')
    with _pinned_copy_source(source) as incoming:
        opened = os.fstat(incoming)
        if _copy_identity(opened) != before:
            raise ValueError('archive source was substituted')
        try:
            destination_details = destination.lstat()
        except FileNotFoundError:
            destination_details = None
        if destination_details is not None:
            validate(destination)
            existing_identity = _copy_identity(destination_details)
            if existing_identity[:2] == before[:2]:
                raise ValueError('archive cannot alias its source')
            with _pinned_copy_source(destination) as existing:
                if _copy_identity(os.fstat(existing)) != existing_identity:
                    raise ValueError('archive destination was substituted')
                _verify_copy_bytes(existing, expected_size, expected_sha256)
                if _copy_identity(destination.lstat()) != existing_identity:
                    raise ValueError('archive destination changed')
                _verify_copy_bytes(incoming, expected_size, expected_sha256)
                if (_copy_identity(source.lstat()) != before
                    or os.fstat(incoming).st_ctime_ns != opened.st_ctime_ns):
                    raise ValueError('archive source changed')
                flush_directory(destination.parent)
                return
        temporary = destination.with_name(f'.{destination.name}.{uuid.uuid4().hex}.tmp')
        _checked_path(temporary, trusted_root)
        installer_mutation_checkpoint()
        outgoing = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        identity = None
        try:
            try:
                identity = os.fstat(outgoing)
                _check_temporary(temporary, trusted_root, identity)
                protect(temporary)
                validate(temporary)
                _check_temporary(temporary, trusted_root, identity)
                installer_mutation_checkpoint()
                total, digest = 0, hashlib.sha256()
                while block := os.read(incoming, 1024 * 1024):
                    total += len(block)
                    if total > expected_size:
                        raise ValueError('archive source exceeded its bound')
                    digest.update(block)
                    remaining = memoryview(block)
                    while remaining:
                        written = os.write(outgoing, remaining)
                        if written <= 0:
                            raise OSError('short archive write')
                        remaining = remaining[written:]
                if (total != expected_size or digest.hexdigest() != expected_sha256
                    or _copy_identity(os.fstat(incoming)) != before or _copy_identity(source.lstat()) != before
                    or os.fstat(incoming).st_ctime_ns != opened.st_ctime_ns):
                    raise ValueError('archive source identity differs')
                os.fsync(outgoing)
            finally:
                os.close(outgoing)
            _checked_path(destination, trusted_root)
            if destination.exists():
                raise ValueError('archive destination appeared during publication')
            _check_temporary(temporary, trusted_root, identity)
            installer_mutation_checkpoint()
            os.replace(temporary, destination)
            flush_directory(destination.parent)
        finally:
            if identity is not None:
                _remove_temporary(temporary, trusted_root, identity)


def publish_prepared(
    source: Path, path: Path, *, expected_bytes: bytes, trusted_root: Path,
    max_bytes: int, validate: Callable[[Path], None] | None = None,
) -> None:
    """Consume an already protected, file/directory-flushed same-parent slot.

    The caller prepared it with write_bytes_atomic before exhaustion. No new
    payload allocation or writer is used here. A failed metadata flush remains
    an error even when the exact restoration bytes have become visible.
    """
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    if not isinstance(expected_bytes, bytes) or len(expected_bytes) > max_bytes:
        raise ValueError("prepared state bytes exceed bound")
    prepared = _checked_path(source, trusted_root)
    destination = _checked_path(path, trusted_root)
    if prepared == destination or prepared.parent != destination.parent:
        raise ValueError("prepared state must be a different same-parent file")
    descriptor = os.open(prepared, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        identity = os.fstat(descriptor)
        _reject_reparse(identity)
        _check_temporary(prepared, trusted_root, identity)
        if not stat.S_ISREG(identity.st_mode) or identity.st_size != len(expected_bytes):
            raise ValueError("prepared state size is invalid")
        if validate is not None:
            validate(prepared)
        data = bytearray()
        while len(data) <= max_bytes:
            block = os.read(descriptor, min(4096, max_bytes + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        if bytes(data) != expected_bytes:
            raise ValueError("prepared state contents differ")
        _check_temporary(prepared, trusted_root, identity)
    finally:
        os.close(descriptor)
    _checked_path(destination, trusted_root)
    _check_temporary(prepared, trusted_root, identity)
    installer_mutation_checkpoint()
    os.replace(prepared, destination)
    flush_directory(destination.parent)


def durable_unlink(path: Path, *, trusted_root: Path, missing_ok: bool = False) -> None:
    """Delete a regular state leaf and flush its containing directory."""
    destination = _checked_path(path, trusted_root)
    installer_mutation_checkpoint()
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
    installer_mutation_checkpoint()
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
