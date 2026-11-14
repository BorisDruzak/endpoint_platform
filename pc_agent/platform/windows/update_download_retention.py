"""Coordinate online Core transfers and retire verified Windows download files."""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
from itertools import islice
import os
from pathlib import Path
import re
import stat

from .acl import WindowsAclError
from .disk_readiness import MAX_ARTIFACT_BYTES
from .durable_state import _check_directories, _checked_path, durable_unlink
from .update_paths import WindowsUpdatePaths
from .update_transaction import UpdateInProgress, _assert_state_security


# Exclusive to runtimes that hold the transfer lock. The HTTP downloader
# writes its own exclusive temporary alongside the staging destination.
TRANSFER_PREFIX = ".core-transfer-"
_STAGING = r"\.core-transfer-[0-9a-f]{32}\.staging"
_TRANSFER_FILE = re.compile(rf"(?:{_STAGING}|\.{_STAGING}\.[0-9a-f]{{32}}\.tmp)")
_SCAN_LIMIT = 4096
_DELETE_LIMIT = 16


def _assert_cache_security(path: Path) -> None:
    try:
        _assert_state_security(path)
    except Exception as error:
        raise ValueError("Core download cache security cannot be verified") from error


@contextmanager
def own_core_download(paths: WindowsUpdatePaths):
    """Keep one online transfer owner across awaits without holding the update mutex."""
    root = paths.updates_root
    lock = _checked_path(root / ".core-download.lock", root)
    _assert_cache_security(root)
    try:
        stream = lock.open("x+b")
    except FileExistsError:
        if lock.lstat().st_nlink != 1:
            raise ValueError("Core download lock is not a unique file")
        _assert_cache_security(lock)
        stream = lock.open("r+b")
    with stream:
        details = os.fstat(stream.fileno())
        if not os.path.samestat(lock.lstat(), details) or details.st_nlink != 1 or details.st_size:
            raise ValueError("Core download lock identity is invalid")
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise UpdateInProgress("Core download already active") from error
        # Closing the descriptor releases ownership, including on process exit.
        # Keep the lock leaf itself so future owners always open the same inode.
        yield


def retire_interrupted_core_downloads(paths: WindowsUpdatePaths) -> None:
    """Reclaim closed transfer scratch files under both ownership boundaries."""
    try:
        _check_directories(paths.downloads_root)
        _assert_cache_security(paths.downloads_root)
        attempts = 0
        with os.scandir(paths.downloads_root) as entries:
            for entry in islice(entries, _SCAN_LIMIT):
                if not _TRANSFER_FILE.fullmatch(entry.name):
                    continue
                artifact = Path(entry.path)
                try:
                    _checked_path(artifact, paths.updates_root)
                    details = artifact.lstat()
                    if details.st_nlink != 1 or details.st_size > MAX_ARTIFACT_BYTES:
                        continue
                    _assert_cache_security(artifact)
                    attempts += 1
                    durable_unlink(artifact, trusted_root=paths.updates_root)
                except (OSError, ValueError):
                    pass
                if attempts >= _DELETE_LIMIT:
                    break
    except (OSError, ValueError):
        # Cache maintenance cannot supersede the update or disk-readiness result.
        return


def retire_update_download(paths: WindowsUpdatePaths, pending: dict, *, assert_security=None) -> bool:
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
        return False
    if not isinstance(pending.get("artifact_path"), str):
        return False
    artifact = Path(pending["artifact_path"])
    stem = f"build-{version}-{operation}"
    if artifact.parent != paths.downloads_root or not re.fullmatch(
        rf"{re.escape(stem)}(?:-[0-9a-f]{{32}})?\.zip", artifact.name,
    ):
        return False
    try:
        _checked_path(artifact, paths.updates_root)
        details = artifact.lstat()
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1 or details.st_size != size:
            return False
        if assert_security is not None:
            assert_security(artifact)
        with artifact.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if not os.path.samestat(details, opened) or opened.st_size != size:
                return False
            actual = hashlib.sha256()
            remaining = size
            while remaining:
                chunk = stream.read(min(remaining, 1024 * 1024))
                if not chunk:
                    return False
                actual.update(chunk)
                remaining -= len(chunk)
            if stream.read(1) or actual.hexdigest() != digest:
                return False
        observed = artifact.lstat()
        if (
            not os.path.samestat(details, observed)
            or observed.st_size != size
            or observed.st_mtime_ns != details.st_mtime_ns
            or observed.st_ctime_ns != details.st_ctime_ns
        ):
            return False
        durable_unlink(artifact, trusted_root=paths.updates_root)
        return True
    except (OSError, ValueError, WindowsAclError):
        # Cache cleanup cannot change an already durable terminal result.
        return False
