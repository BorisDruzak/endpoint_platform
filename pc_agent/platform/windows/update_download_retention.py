"""Coordinate online Core transfers and retire verified Windows download files."""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Callable
from contextlib import contextmanager
import hashlib
from itertools import islice
import os
from pathlib import Path
import re
import stat

from .acl import WindowsAclError
from .disk_readiness import MAX_ARTIFACT_BYTES
from .durable_state import (
    _check_directories, _checked_path, durable_unlink, flush_directory, write_json_atomic,
)
from .update_paths import WindowsUpdatePaths
from .update_transaction import UpdateInProgress, _assert_state_security, _read_state


# Exclusive to runtimes that hold the transfer lock. The HTTP downloader
# writes its own exclusive temporary alongside the staging destination.
TRANSFER_PREFIX = ".core-transfer-"
_STAGING = r"\.core-transfer-[0-9a-f]{32}\.staging"
_TRANSFER_FILE = re.compile(rf"(?:{_STAGING}|\.{_STAGING}\.[0-9a-f]{{32}}\.tmp)")
_SCAN_LIMIT = 4096
_DELETE_LIMIT = 16
_OPERATION = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
_RETIREMENT = re.compile(rf"\.core-retire-(?P<operation>{_OPERATION})\.json")
_RETIREMENT_FIELDS = frozenset(("version", "operation_id", "artifact_path", "sha256", "size"))
_RETIREMENT_LIMIT = 4096
_RETIREMENT_CURSOR = ".core-retirement-cursor.json"
_SHARING_ERRORS = {32, 33}  # ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION


class CoreDownloadContentChanged(RuntimeError):
    """A protected archive has different bytes from its publication record."""


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


def _download_path(paths: WindowsUpdatePaths, pending: dict) -> Path | None:
    version, operation = pending.get("version"), pending.get("operation_id")
    digest, size = pending.get("sha256"), pending.get("size")
    if (
        not isinstance(version, str) or not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+-]{0,127}", version)
        or not isinstance(operation, str)
        or not re.fullmatch(_OPERATION, operation)
        or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
        or type(size) is not int or not 0 < size <= MAX_ARTIFACT_BYTES
    ):
        return None
    if not isinstance(pending.get("artifact_path"), str):
        return None
    artifact = Path(pending["artifact_path"])
    stem = f"build-{version}-{operation}"
    if artifact.parent != paths.downloads_root or not re.fullmatch(
        rf"{re.escape(stem)}(?:-[0-9a-f]{{32}})?\.zip", artifact.name,
    ):
        return None
    return artifact


def _save_deferred_retirement(
    paths: WindowsUpdatePaths, pending: dict, protect: Callable[[Path], None],
) -> None:
    root = paths.updates_root
    receipt = root / f".core-retire-{pending['operation_id']}.json"
    metadata = {name: pending[name] for name in _RETIREMENT_FIELDS}
    try:
        _assert_cache_security(root)
        # An interrupted cleanup may present the same terminal receipt again.
        existing = _read_state(receipt, _RETIREMENT_LIMIT)
        if existing is None:
            write_json_atomic(receipt, metadata, trusted_root=root, max_bytes=_RETIREMENT_LIMIT,
                              protect=protect)
        elif existing == metadata:
            flush_directory(root)
    except (OSError, ValueError, WindowsAclError):
        # Cache maintenance cannot invalidate an accepted or reported update.
        pass


def retire_update_download(
    paths: WindowsUpdatePaths,
    pending: dict,
    *,
    assert_security: Callable[[Path], None] | None = None,
    protect_receipt: Callable[[Path], None] | None = None,
    signal_changed_content: bool = False,
) -> bool:
    """Delete a verified cache leaf or signal a content change to its writer."""
    artifact = _download_path(paths, pending)
    if artifact is None:
        return False
    digest, size = pending["sha256"], pending["size"]
    try:
        _checked_path(artifact, paths.updates_root)
        details = artifact.lstat()
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            return False
        if assert_security is not None:
            assert_security(artifact)
        if details.st_size != size:
            if signal_changed_content:
                raise CoreDownloadContentChanged("Core download archive size differs")
            return False
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
            if stream.read(1):
                return False
        observed = artifact.lstat()
        if (
            not os.path.samestat(details, observed)
            or observed.st_size != size
            or observed.st_mtime_ns != details.st_mtime_ns
            or observed.st_ctime_ns != details.st_ctime_ns
        ):
            return False
        if actual.hexdigest() != digest:
            if signal_changed_content:
                raise CoreDownloadContentChanged("Core download archive digest differs")
            return False
        durable_unlink(artifact, trusted_root=paths.updates_root)
        return True
    except OSError as error:
        if protect_receipt is not None and getattr(error, "winerror", None) in _SHARING_ERRORS:
            _save_deferred_retirement(paths, pending, protect_receipt)
        return False
    except (ValueError, WindowsAclError):
        # Cache cleanup cannot change an already durable terminal result.
        return False


def retry_deferred_core_downloads(
    paths: WindowsUpdatePaths, *, protect: Callable[[Path], None],
) -> None:
    """Retry a bounded set of terminal archives without starving later receipts."""
    root = paths.updates_root
    cursor_path = root / _RETIREMENT_CURSOR
    try:
        _check_directories(root)
        _assert_cache_security(root)
        with os.scandir(root) as entries:
            names = sorted(
                entry.name for entry in islice(entries, _SCAN_LIMIT) if _RETIREMENT.fullmatch(entry.name)
            )
        if not names:
            return
        try:
            cursor = _read_state(cursor_path, _RETIREMENT_LIMIT)
        except (OSError, ValueError, WindowsAclError):
            cursor = None
        if not isinstance(cursor, str) or _RETIREMENT.fullmatch(cursor) is None:
            cursor = ""
        offset = bisect_right(names, cursor)
        attempts = 0
        bytes_left = MAX_ARTIFACT_BYTES
        last = cursor
        for name in names[offset:] + names[:offset]:
            previous, last = last, name
            receipt = root / name
            try:
                metadata = _read_state(receipt, _RETIREMENT_LIMIT)
                if (not isinstance(metadata, dict) or metadata.keys() != _RETIREMENT_FIELDS
                        or metadata["operation_id"] != _RETIREMENT.fullmatch(name)["operation"]):
                    continue
                artifact = _download_path(paths, metadata)
                if artifact is None:
                    continue
                if metadata["size"] > bytes_left:
                    # Give this receipt a full byte budget on the next check.
                    last = previous
                    break
                _checked_path(artifact, root)
                _assert_cache_security(artifact.parent)
                attempts += 1
                try:
                    artifact.lstat()
                except FileNotFoundError:
                    # Finish the archive barrier after an interrupted retry.
                    flush_directory(artifact.parent)
                    retired = True
                else:
                    bytes_left -= metadata["size"]
                    retired = retire_update_download(paths, metadata, assert_security=_assert_cache_security)
                if retired:
                    durable_unlink(receipt, trusted_root=root, missing_ok=True)
            except (OSError, ValueError, WindowsAclError):
                pass
            if attempts >= _DELETE_LIMIT:
                break
        else:
            return
        if last != cursor:
            write_json_atomic(cursor_path, last, trusted_root=root, max_bytes=_RETIREMENT_LIMIT, protect=protect)
    except (OSError, ValueError, WindowsAclError):
        # Cursor persistence is best effort. Receipts remain the cleanup authority.
        return
