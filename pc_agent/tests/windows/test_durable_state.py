"""Durability boundaries, fail-closed paths, and native filesystem coverage."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import durable_state as durable


def test_write_order_and_protection(tmp_path, monkeypatch):
    target = tmp_path / "state.json"
    events = []
    real_open, real_write, real_fsync, real_replace = os.open, os.write, os.fsync, os.replace

    def create(path, flags, mode=0o777):
        assert Path(path).parent == tmp_path
        assert flags & os.O_EXCL and flags & os.O_CREAT
        assert mode == 0o600
        events.append("create")
        return real_open(path, flags, mode)

    def protect(path):
        assert path.read_bytes() == b""
        assert not target.exists()
        events.append("protect")

    def write(fd, data):
        events.append("bytes")
        return real_write(fd, data)

    def fsync(fd):
        events.append("file_fsync")
        return real_fsync(fd)

    def replace(source, destination):
        assert Path(source).read_bytes() == b'{"ok":true}'
        events.append("replace")
        real_replace(source, destination)

    monkeypatch.setattr(durable.os, "open", create)
    monkeypatch.setattr(durable.os, "write", write)
    monkeypatch.setattr(durable.os, "fsync", fsync)
    monkeypatch.setattr(durable.os, "replace", replace)
    monkeypatch.setattr(durable, "flush_directory", lambda path: events.append("directory_fsync"))
    durable.write_json_atomic(target, {"ok": True}, trusted_root=tmp_path, max_bytes=20, protect=protect)
    assert events == ["create", "protect", "bytes", "file_fsync", "replace", "directory_fsync"]
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.parametrize("boundary", ["create", "protect", "write", "fsync", "replace", "directory"])
@pytest.mark.parametrize("after", [False, True])
def test_failure_boundaries_do_not_claim_success(tmp_path, monkeypatch, boundary, after):
    target = tmp_path / "state.json"
    target.write_bytes(b'{"old":true}')

    def fail(function):
        def wrapped(*args, **kwargs):
            if not after:
                raise OSError("injected boundary")
            function(*args, **kwargs)
            raise OSError("injected boundary")
        return wrapped

    protect = lambda path: None
    monkeypatch.setattr(durable, "flush_directory", lambda path: None)
    if boundary == "protect":
        protect = fail(protect)
    elif boundary == "create" and after:
        # Fail immediately after exclusive create and fstat while the primitive
        # owns the descriptor. Cleanup must close/remove it itself.
        real_check = durable._check_temporary
        checks = 0

        def check(*args):
            nonlocal checks
            checks += 1
            if checks == 1:
                raise OSError("injected boundary")
            return real_check(*args)

        monkeypatch.setattr(durable, "_check_temporary", check)
    elif boundary == "directory":
        monkeypatch.setattr(durable, "flush_directory", fail(durable.flush_directory))
    else:
        name = {"create": "open", "write": "write", "fsync": "fsync", "replace": "replace"}[boundary]
        monkeypatch.setattr(durable.os, name, fail(getattr(durable.os, name)))
    with pytest.raises(OSError, match="injected boundary"):
        durable.write_json_atomic(target, {"new": True}, trusted_root=tmp_path, max_bytes=30, protect=protect)
    published = boundary == "directory" or boundary == "replace" and after
    assert json.loads(target.read_bytes()) == ({"new": True} if published else {"old": True})
    assert list(tmp_path.iterdir()) == [target]


def test_short_writes_preserve_exact_bytes(tmp_path, monkeypatch):
    real_write = os.write
    monkeypatch.setattr(durable.os, "write", lambda fd, data: real_write(fd, data[:2]))
    monkeypatch.setattr(durable, "flush_directory", lambda path: None)
    target = tmp_path / "bytes"
    durable.write_bytes_atomic(target, b"1234567", trusted_root=tmp_path, max_bytes=7)
    assert target.read_bytes() == b"1234567"


def test_prepared_publication_needs_no_new_payload_allocation(tmp_path, monkeypatch):
    source, target = tmp_path / "prepared", tmp_path / "current"
    durable.write_bytes_atomic(source, b"known-good", trusted_root=tmp_path, max_bytes=10)
    target.write_bytes(b"candidate")
    def exhausted(*_):
        raise OSError("payload allocation exhausted")
    monkeypatch.setattr(durable.os, "write", exhausted)
    durable.publish_prepared(source, target, expected_bytes=b"known-good", trusted_root=tmp_path, max_bytes=10)
    assert target.read_bytes() == b"known-good"
    assert not source.exists()


@pytest.mark.parametrize("problem", ["different_bytes", "hardlink", "different_parent", "too_large"])
def test_prepared_publication_rejects_unsafe_source(tmp_path, problem):
    source, target = tmp_path / "prepared", tmp_path / "current"
    source.write_bytes(b"known-good")
    target.write_bytes(b"candidate")
    expected, maximum = b"known-good", 10
    if problem == "different_bytes":
        expected = b"different"
    elif problem == "hardlink":
        os.link(source, tmp_path / "alias")
    elif problem == "different_parent":
        (tmp_path / "other").mkdir()
        target = tmp_path / "other" / "current"
        target.write_bytes(b"candidate")
    else:
        maximum = 5
    with pytest.raises(ValueError):
        durable.publish_prepared(source, target, expected_bytes=expected, trusted_root=tmp_path, max_bytes=maximum)
    assert target.read_bytes() == b"candidate"
    assert source.read_bytes() == b"known-good"


@pytest.mark.parametrize("fault", ["replacement", "directory", "validator"])
def test_prepared_publication_failure_never_claims_durable_success(tmp_path, monkeypatch, fault):
    source, target = tmp_path / "prepared", tmp_path / "current"
    durable.write_bytes_atomic(source, b"known-good", trusted_root=tmp_path, max_bytes=10)
    target.write_bytes(b"candidate")
    def fail(*_):
        raise OSError("prepared publication interrupted")
    validator = None
    if fault == "replacement":
        monkeypatch.setattr(durable.os, "replace", fail)
    elif fault == "directory":
        monkeypatch.setattr(durable, "flush_directory", fail)
    else:
        validator = fail
    with pytest.raises(OSError, match="publication interrupted"):
        durable.publish_prepared(source, target, expected_bytes=b"known-good", trusted_root=tmp_path,
            max_bytes=10, validate=validator)
    assert target.read_bytes() == (b"known-good" if fault == "directory" else b"candidate")
    assert source.exists() == (fault != "directory")


def test_prepared_publication_rejects_handle_path_substitution(tmp_path, monkeypatch):
    source, target = tmp_path / "prepared", tmp_path / "current"
    source.write_bytes(b"known-good")
    target.write_bytes(b"candidate")
    original = durable.os.fstat
    def different_handle(descriptor):
        details = original(descriptor)
        return SimpleNamespace(st_dev=details.st_dev, st_ino=details.st_ino + 1,
            st_mode=details.st_mode, st_nlink=details.st_nlink, st_size=details.st_size)
    monkeypatch.setattr(durable.os, "fstat", different_handle)
    with pytest.raises(ValueError, match="identity"):
        durable.publish_prepared(source, target, expected_bytes=b"known-good", trusted_root=tmp_path, max_bytes=10)
    assert target.read_bytes() == b"candidate"


@pytest.mark.skipif(os.name != "nt", reason="native selector ACL carry-forward")
def test_native_prepared_slot_preserves_selector_acl_and_rejects_acl_change(tmp_path):
    from pc_agent.platform.windows.acl import preserve_state_file_permissions, assert_state_file_permissions_match, WindowsAclError
    import win32security
    source, target = tmp_path / "prepared", tmp_path / "current"
    target.write_bytes(b"old")
    durable.write_bytes_atomic(source, b"old", trusted_root=tmp_path, max_bytes=3,
        protect=lambda temporary: preserve_state_file_permissions(target, temporary))
    assert_state_file_permissions_match(target, source)
    changed = win32security.ACL()
    changed.AddAccessAllowedAce(win32security.ACL_REVISION, 0x00120089, win32security.ConvertStringSidToSid("S-1-1-0"))
    win32security.SetNamedSecurityInfo(str(source), win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None, None, changed, None)
    with pytest.raises(WindowsAclError):
        durable.publish_prepared(source, target, expected_bytes=b"old", trusted_root=tmp_path, max_bytes=3,
            validate=lambda prepared: assert_state_file_permissions_match(target, prepared))
    assert target.read_bytes() == b"old" and source.exists()


def test_zero_write_fails_and_cleans_temporary(tmp_path, monkeypatch):
    monkeypatch.setattr(durable.os, "write", lambda fd, data: 0)
    with pytest.raises(OSError, match="short write"):
        durable.write_bytes_atomic(tmp_path / "state", b"x", trusted_root=tmp_path, max_bytes=1)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("payload", [{"text": "привет"}, [{"event": "ready"}, {"event": "rollback"}]])
def test_dictionary_and_journal_list_round_trip(tmp_path, payload):
    target = tmp_path / "state.json"
    durable.write_json_atomic(target, payload, trusted_root=tmp_path, max_bytes=100)
    assert json.loads(target.read_bytes()) == payload


@pytest.mark.parametrize("max_bytes", [0, -1, True, 1.5])
def test_invalid_bounds_are_rejected_without_mutation(tmp_path, max_bytes):
    with pytest.raises(ValueError, match="max_bytes"):
        durable.write_bytes_atomic(tmp_path / "state", b"", trusted_root=tmp_path, max_bytes=max_bytes)
    assert list(tmp_path.iterdir()) == []


def test_byte_bound_and_invalid_json_leave_old_state(tmp_path):
    target = tmp_path / "state"
    target.write_bytes(b"old")
    for payload in [{"x": "é"}, {"x": float("nan")}, object()]:
        with pytest.raises((ValueError, TypeError)):
            durable.write_json_atomic(target, payload, trusted_root=tmp_path, max_bytes=5)
    with pytest.raises(ValueError, match="size"):
        durable.write_bytes_atomic(target, b"123456", trusted_root=tmp_path, max_bytes=5)
    assert target.read_bytes() == b"old"
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.skipif(os.name != "nt", reason="Windows filename aliases")
@pytest.mark.parametrize("name", ["state.", "state ", "CON", "NUL", "COM1.json"])
def test_windows_aliases_rejected(tmp_path, name):
    with pytest.raises(ValueError, match="alias"):
        durable.write_bytes_atomic(tmp_path / name, b"x", trusted_root=tmp_path, max_bytes=1)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("kind", ["outside", "parent_traversal", "root", "directory", "missing_parent", "stream"])
def test_unsafe_destination_rejected(tmp_path, kind):
    target = {
        "outside": tmp_path.parent / "outside-state",
        "parent_traversal": tmp_path / "nested" / ".." / "state",
        "root": tmp_path,
        "directory": tmp_path / "directory",
        "missing_parent": tmp_path / "missing" / "state",
        "stream": tmp_path / "state:alternate",
    }[kind]
    (tmp_path / "directory").mkdir()
    with pytest.raises((ValueError, OSError)):
        durable.write_bytes_atomic(target, b"x", trusted_root=tmp_path, max_bytes=1)
    assert list(tmp_path.iterdir()) == [tmp_path / "directory"]


@pytest.mark.parametrize("kind", ["root", "parent", "destination"])
def test_actual_symlinks_rejected(tmp_path, kind):
    safe = tmp_path / "safe"
    safe.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "victim"
    victim.write_bytes(b"unchanged")
    link = safe / "link"
    try:
        link.symlink_to(victim if kind == "destination" else outside, target_is_directory=kind != "destination")
    except OSError as error:
        pytest.skip(f"native symlink permission unavailable: {error}")
    root = link if kind == "root" else safe
    target = link if kind == "destination" else link / "victim"
    with pytest.raises(ValueError, match="reparse"):
        durable.write_bytes_atomic(target, b"x", trusted_root=root, max_bytes=1)
    assert victim.read_bytes() == b"unchanged"


@pytest.mark.parametrize("kind", ["root", "parent", "destination", "temporary"])
def test_reparse_attribute_rejected(tmp_path, monkeypatch, kind):
    parent = tmp_path / "parent"
    parent.mkdir()
    target = parent / "state"
    target.write_bytes(b"old")
    real_lstat = Path.lstat

    def lstat(path):
        info = real_lstat(path)
        bad = path == {"root": tmp_path, "parent": parent, "destination": target}.get(kind)
        bad = bad or kind == "temporary" and path.name.endswith(".tmp")
        if bad:
            return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400, st_dev=info.st_dev, st_ino=info.st_ino)
        return info

    monkeypatch.setattr(Path, "lstat", lstat)
    with pytest.raises(ValueError, match="reparse"):
        durable.write_bytes_atomic(target, b"x", trusted_root=tmp_path, max_bytes=1)
    assert target.read_bytes() == b"old"
    # A changed/reparse temporary must not be followed or removed by cleanup.
    monkeypatch.setattr(Path, "lstat", real_lstat)
    for path in parent.glob("*.tmp"):
        path.unlink()


def test_exclusive_collision_never_deletes_another_file(tmp_path, monkeypatch):
    monkeypatch.setattr(durable.uuid, "uuid4", lambda: SimpleNamespace(hex="collision"))
    foreign = tmp_path / ".state.collision.tmp"
    foreign.write_bytes(b"foreign")
    with pytest.raises(FileExistsError):
        durable.write_bytes_atomic(tmp_path / "state", b"x", trusted_root=tmp_path, max_bytes=1)
    assert foreign.read_bytes() == b"foreign"


def test_substituted_temporary_is_not_published_or_cleaned(tmp_path):
    target = tmp_path / "state"
    target.write_bytes(b"old")
    captured = []

    def protect(path):
        captured.append(path)
        # Windows denies deleting an open CRT file. Simulate substitution by
        # renaming at the post-close replace boundary in the separate test.
        os.link(path, tmp_path / "extra-link")

    with pytest.raises(ValueError, match="temporary"):
        durable.write_bytes_atomic(target, b"x", trusted_root=tmp_path, max_bytes=1, protect=protect)
    assert target.read_bytes() == b"old"
    assert captured[0].exists()


def test_post_close_substitution_and_unsafe_cleanup(tmp_path, monkeypatch):
    target = tmp_path / "state"
    target.write_bytes(b"old")
    real_close = os.close
    captured = []
    real_open = os.open

    def create(path, flags, mode=0o777):
        captured.append(Path(path))
        return real_open(path, flags, mode)

    def close(fd):
        real_close(fd)
        temporary = captured[0]
        temporary.rename(tmp_path / "original")
        temporary.write_bytes(b"substituted")

    monkeypatch.setattr(durable.os, "open", create)
    monkeypatch.setattr(durable.os, "close", close)
    with pytest.raises(ValueError, match="temporary"):
        durable.write_bytes_atomic(target, b"x", trusted_root=tmp_path, max_bytes=1)
    assert target.read_bytes() == b"old"
    assert captured[0].read_bytes() == b"substituted"


def test_destination_changed_to_reparse_before_publication(tmp_path, monkeypatch):
    target = tmp_path / "state"
    target.write_bytes(b"old")
    real_close, real_lstat = os.close, Path.lstat
    closed = False

    def close(fd):
        nonlocal closed
        real_close(fd)
        closed = True

    def lstat(path):
        info = real_lstat(path)
        if path == target and closed:
            return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
        return info

    monkeypatch.setattr(durable.os, "close", close)
    monkeypatch.setattr(Path, "lstat", lstat)
    with pytest.raises(ValueError, match="reparse"):
        durable.write_bytes_atomic(target, b"x", trusted_root=tmp_path, max_bytes=1)
    assert target.read_bytes() == b"old"
    assert list(tmp_path.iterdir()) == [target]


def test_durable_unlink_order_missing_and_failure(tmp_path, monkeypatch):
    target = tmp_path / "state"
    target.write_bytes(b"x")
    events = []
    real_unlink = Path.unlink

    def unlink(path, *args, **kwargs):
        events.append("unlink")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", unlink)
    monkeypatch.setattr(durable, "flush_directory", lambda path: events.append("directory_fsync"))
    durable.durable_unlink(target, trusted_root=tmp_path)
    assert events == ["unlink", "directory_fsync"]
    events.clear()
    durable.durable_unlink(target, trusted_root=tmp_path, missing_ok=True)
    # Flush even an already missing marker: a previous delete may have failed its flush.
    assert events == ["unlink", "directory_fsync"]
    with pytest.raises(FileNotFoundError):
        durable.durable_unlink(target, trusted_root=tmp_path)
    monkeypatch.setattr(durable, "flush_directory", lambda path: (_ for _ in ()).throw(OSError("flush failed")))
    target.write_bytes(b"x")
    with pytest.raises(OSError, match="flush failed"):
        durable.durable_unlink(target, trusted_root=tmp_path)
    assert not target.exists()


def test_unlink_failure_does_not_flush_or_claim_success(tmp_path, monkeypatch):
    target = tmp_path / "state"
    target.write_bytes(b"x")
    monkeypatch.setattr(Path, "unlink", lambda path: (_ for _ in ()).throw(OSError("delete failed")))
    monkeypatch.setattr(durable, "flush_directory", lambda path: pytest.fail("delete failed before flush"))
    with pytest.raises(OSError, match="delete failed"):
        durable.durable_unlink(target, trusted_root=tmp_path)
    assert target.read_bytes() == b"x"


def test_cleanup_error_propagates_without_deleting_original(tmp_path, monkeypatch):
    target = tmp_path / "state"
    target.write_bytes(b"old")

    def fsync(fd):
        raise OSError("fsync failed")

    def unlink(path):
        raise OSError("cleanup failed")

    monkeypatch.setattr(durable.os, "fsync", fsync)
    monkeypatch.setattr(Path, "unlink", unlink)
    with pytest.raises(OSError, match="cleanup failed") as caught:
        durable.write_bytes_atomic(target, b"x", trusted_root=tmp_path, max_bytes=1)
    assert str(caught.value.__context__) == "fsync failed"
    assert target.read_bytes() == b"old"


def test_durable_unlink_rejects_escape_and_reparse(tmp_path, monkeypatch):
    target = tmp_path / "state"
    target.write_bytes(b"old")
    real_lstat = Path.lstat

    def lstat(path):
        info = real_lstat(path)
        return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400) if path == target else info

    monkeypatch.setattr(Path, "lstat", lstat)
    with pytest.raises(ValueError, match="reparse"):
        durable.durable_unlink(target, trusted_root=tmp_path)
    with pytest.raises(ValueError, match="trusted root"):
        durable.durable_unlink(tmp_path.parent / "other", trusted_root=tmp_path, missing_ok=True)
    assert target.read_bytes() == b"old"


@pytest.mark.skipif(os.name != "nt", reason="genuine Windows DACL carry-over")
def test_native_windows_protected_acl_survives_publication(tmp_path):
    import win32api
    import win32con
    import win32security

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    finally:
        token.Close()
    target = tmp_path / "protected"

    def protect(path):
        assert path.read_bytes() == b""
        dacl = win32security.ACL()
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.GENERIC_ALL, sid)
        win32security.SetNamedSecurityInfo(
            str(path), win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            None, None, dacl, None,
        )

    durable.write_bytes_atomic(target, b"protected", trusted_root=tmp_path, max_bytes=9, protect=protect)
    descriptor = win32security.GetFileSecurity(str(target), win32security.DACL_SECURITY_INFORMATION)
    assert descriptor.GetSecurityDescriptorControl()[0] & win32security.SE_DACL_PROTECTED
    dacl = descriptor.GetSecurityDescriptorDacl()
    assert dacl.GetAceCount() == 1
    assert dacl.GetAce(0)[2] == sid
    assert target.read_bytes() == b"protected"


def test_native_filesystem_flush_write_and_delete(tmp_path):
    target = tmp_path / "native"
    durable.flush_directory(tmp_path)
    durable.write_bytes_atomic(target, b"native\x00bytes", trusted_root=tmp_path, max_bytes=12)
    assert target.read_bytes() == b"native\x00bytes"
    durable.durable_unlink(target, trusted_root=tmp_path)
    assert not target.exists()


@pytest.mark.parametrize("failure", [None, "create", "flush", "reparse"])
def test_windows_api_order_and_errors(tmp_path, monkeypatch, failure):
    events = []

    class Handle:
        def Close(self):
            events.append("close")

    def create(*args):
        assert args == (str(tmp_path), 3, 28, None, 32, 64 | 128, None)
        events.append("create")
        if failure == "create":
            raise OSError("create failed")
        return Handle()

    def flush(handle):
        events.append("flush")
        if failure == "flush":
            raise OSError("flush failed")

    constants = SimpleNamespace(GENERIC_READ=1, GENERIC_WRITE=2, FILE_SHARE_READ=4, FILE_SHARE_WRITE=8,
                               FILE_SHARE_DELETE=16, OPEN_EXISTING=32, FILE_FLAG_BACKUP_SEMANTICS=64)
    monkeypatch.setitem(sys.modules, "win32con", constants)
    monkeypatch.setitem(sys.modules, "pywintypes", SimpleNamespace(error=type("NativeError", (Exception,), {})))
    monkeypatch.setitem(sys.modules, "win32file", SimpleNamespace(CreateFile=create, FlushFileBuffers=flush,
                                                               GetFileInformationByHandle=lambda handle: (0x400 if failure == "reparse" else 0,),
                                                               FILE_FLAG_OPEN_REPARSE_POINT=128))
    monkeypatch.setattr(durable, "_WINDOWS", True)
    if failure == "reparse":
        with pytest.raises(ValueError, match="reparse"):
            durable.flush_directory(tmp_path)
    elif failure:
        with pytest.raises(OSError, match=f"{failure} failed"):
            durable.flush_directory(tmp_path)
    else:
        durable.flush_directory(tmp_path)
    assert events == (["create"] if failure == "create" else
                      ["create", "close"] if failure == "reparse" else ["create", "flush", "close"])


@pytest.mark.parametrize("failure", [None, "fsync"])
def test_posix_directory_branch_simulated(tmp_path, monkeypatch, failure):
    events = []
    monkeypatch.setattr(durable, "_WINDOWS", False)
    monkeypatch.setattr(durable.os, "open", lambda path, flags: events.append(("open", flags)) or 123)
    monkeypatch.setattr(durable.os, "close", lambda fd: events.append(("close", fd)))

    def fsync(fd):
        events.append(("fsync", fd))
        if failure:
            raise OSError("fsync failed")

    monkeypatch.setattr(durable.os, "fsync", fsync)
    if failure:
        with pytest.raises(OSError, match="fsync failed"):
            durable.flush_directory(tmp_path)
    else:
        durable.flush_directory(tmp_path)
    assert events == [("open", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)),
                      ("fsync", 123), ("close", 123)]


@pytest.mark.skipif(sys.platform != "win32", reason="native pywin32 error type")
@pytest.mark.parametrize("stage", ["create", "info", "flush", "close"])
def test_native_directory_errors_are_portable_with_code_and_cause(tmp_path, monkeypatch, stage):
    import pywintypes
    import win32file
    error = pywintypes.error(5, "directory " + stage, "native directory failure")
    events = []
    def step(name, result=None):
        events.append(name)
        if stage == name:
            raise error
        return result
    class Handle:
        def Close(self):
            step("close")
    monkeypatch.setattr(win32file, "CreateFile", lambda *args: step("create", Handle()))
    monkeypatch.setattr(win32file, "GetFileInformationByHandle", lambda handle: step("info", (0,)))
    monkeypatch.setattr(win32file, "FlushFileBuffers", lambda handle: step("flush"))
    with pytest.raises(OSError) as caught:
        durable.flush_directory(tmp_path)
    assert caught.value.winerror == 5
    assert caught.value.__cause__ is error
    assert events == (["create"] if stage == "create" else ["create", "info", "close"] if stage == "info" else ["create", "info", "flush", "close"])
