"""An image may change loader timestamps; its actual authority must not change."""
from datetime import datetime, timezone
import os
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import durable_state, msi_inventory as msi, update_transaction
from pc_agent.tests.windows.test_foundation_layout import records

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='native Windows file/metadata pins')


@pytest.fixture
def foundation(tmp_path, monkeypatch):
    rows = records(msi)
    for row in rows:
        (tmp_path / row['path']).write_bytes(b'exe')
    monkeypatch.setattr(update_transaction, '_assert_state_security', lambda *_: None)
    return SimpleNamespace(foundation_files=tuple(rows)), tmp_path


def change_access_time(path):
    import win32file
    # Attribute writes are not data writes in the Windows sharing contract.
    handle = win32file.CreateFile(str(path), 0x100, 7, None, 3, 0, None)
    try:
        win32file.SetFileTime(handle, None, datetime.now(timezone.utc), None)
    finally:
        handle.Close()


def test_actual_timestamp_only_change_keeps_verified_bytes(foundation):
    expected, root = foundation
    leaf = root / 'EndpointAgentTray.exe'
    with msi.verified_foundation_bytes(expected, root, allow_execution_metadata=True):
        change_access_time(leaf)


def test_shared_loaded_dependency_uses_the_same_execution_barrier(foundation):
    import hashlib
    from pc_agent.platform.windows.foundation_layout import shared_binding
    expected, root = foundation
    relative = '_foundation-runtime/python312.dll'
    leaf = root / relative
    leaf.parent.mkdir()
    leaf.write_bytes(b'exe')
    file, component = shared_binding(relative)
    row = dict(path=relative, file=file, component=component, size=3,
               sha256=hashlib.sha256(b'exe').hexdigest())
    expected = SimpleNamespace(foundation_files=(*expected.foundation_files, row), foundation_schema=2)
    with msi.verified_foundation_bytes(expected, root, allow_execution_metadata=True):
        change_access_time(leaf)


@pytest.mark.parametrize('action', ['write', 'delete', 'rename'])
def test_all_foundation_data_remains_pinned_during_execution(foundation, action):
    expected, root = foundation
    with msi.verified_foundation_bytes(expected, root, allow_execution_metadata=True):
        for row in expected.foundation_files:
            leaf = root / row['path']
            with pytest.raises(PermissionError):
                if action == 'write':
                    leaf.write_bytes(b'foreign')
                elif action == 'delete':
                    leaf.unlink()
                else:
                    leaf.rename(leaf.with_suffix('.foreign'))


@pytest.mark.parametrize('change', ['attributes', 'safe-dacl-order'])
def test_changed_execution_metadata_is_rejected_without_rebaselining(foundation, change):
    import win32api
    import win32security
    expected, root = foundation
    leaf = root / 'EndpointAgentTray.exe'
    attributes = win32api.GetFileAttributes(str(leaf))
    original = win32security.GetNamedSecurityInfo(str(leaf), 1, 4)
    try:
        with pytest.raises(msi.ProvenanceConflict):
            with msi.verified_foundation_bytes(expected, root, allow_execution_metadata=True):
                if change == 'attributes':
                    win32api.SetFileAttributes(str(leaf), attributes | 1)
                else:
                    before = original.GetSecurityDescriptorDacl()
                    different = win32security.ACL()
                    for index in reversed(range(before.GetAceCount())):
                        ace = before.GetAce(index)
                        different.AddAccessAllowedAceEx(win32security.ACL_REVISION, ace[0][1], ace[1], ace[2])
                    win32security.SetNamedSecurityInfo(str(leaf), 1, 4, None, None, different, None)
    finally:
        win32api.SetFileAttributes(str(leaf), attributes)
        win32security.SetNamedSecurityInfo(str(leaf), 1, 4, None, None, original.GetSecurityDescriptorDacl(), None)


def test_execution_rehashes_timestamp_drift_without_reusing_a_cached_read(foundation, monkeypatch):
    expected, root = foundation
    original = durable_state._verify_copy_bytes
    reads = []
    def verify(*args):
        reads.append(args[0])
        return original(*args)
    monkeypatch.setattr(durable_state, '_verify_copy_bytes', verify)
    with msi.verified_foundation_bytes(expected, root, allow_execution_metadata=True):
        change_access_time(root / 'EndpointAgentTray.exe')
    assert len(reads) == len(expected.foundation_files) + 1


def test_execution_cannot_reuse_an_immutable_read_cache(foundation):
    expected, root = foundation
    with msi.package_read_scope(), msi.immutable_foundation_reads(expected, root):
        with pytest.raises(msi.ProvenanceConflict):
            with msi.verified_foundation_bytes(expected, root, allow_execution_metadata=True):
                pytest.fail('execution entered an immutable read cache')


def test_execution_still_rejects_a_changed_file_identity(foundation):
    expected, root = foundation
    leaf = root / 'EndpointAgentTray.exe'
    with pytest.raises(msi.ProvenanceConflict):
        with msi.verified_foundation_bytes(expected, root, allow_execution_metadata=True):
            before = leaf.stat()
            os.utime(leaf, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))


def test_failed_fresh_hash_never_accepts_timestamp_drift(foundation, monkeypatch):
    expected, root = foundation
    original = durable_state._verify_copy_bytes
    launched = False
    def verify(*args):
        if launched:
            raise ValueError('injected byte proof failure')
        return original(*args)
    monkeypatch.setattr(durable_state, '_verify_copy_bytes', verify)
    with pytest.raises(ValueError, match='injected byte proof failure'):
        with msi.verified_foundation_bytes(expected, root, allow_execution_metadata=True):
            change_access_time(root / 'EndpointAgentTray.exe')
            launched = True


def test_timestamp_only_drift_during_fresh_hash_keeps_exact_execution_proof(foundation, monkeypatch):
    expected, root = foundation
    original = durable_state._verify_copy_bytes
    launched = False
    def verify(*args):
        result = original(*args)
        if launched:
            change_access_time(root / 'EndpointAgentTray.exe')
        return result
    monkeypatch.setattr(durable_state, '_verify_copy_bytes', verify)
    with msi.verified_foundation_bytes(expected, root, allow_execution_metadata=True):
        change_access_time(root / 'EndpointAgentTray.exe')
        launched = True


def test_metadata_read_error_cannot_create_an_accepted_execution_proof(foundation, monkeypatch):
    expected, root = foundation
    original = durable_state.execution_metadata_identity
    launched = False
    def metadata(*args):
        if launched:
            raise OSError('injected native security query failure')
        return original(*args)
    monkeypatch.setattr(durable_state, 'execution_metadata_identity', metadata)
    with pytest.raises(OSError, match='injected native security query failure'):
        with msi.verified_foundation_bytes(expected, root, allow_execution_metadata=True):
            launched = True


def test_initial_hash_cannot_rebaseline_changed_security(foundation, monkeypatch):
    import win32security
    expected, root = foundation
    leaf = root / 'EndpointAgentTray.exe'
    inode = leaf.stat().st_ino
    original_security = win32security.GetNamedSecurityInfo(str(leaf), 1, 4)
    original_verify = durable_state._verify_copy_bytes
    changed = False
    def verify(descriptor, *args):
        nonlocal changed
        result = original_verify(descriptor, *args)
        if not changed and os.fstat(descriptor).st_ino == inode:
            before = original_security.GetSecurityDescriptorDacl()
            different = win32security.ACL()
            for index in reversed(range(before.GetAceCount())):
                ace = before.GetAce(index)
                different.AddAccessAllowedAceEx(win32security.ACL_REVISION, ace[0][1], ace[1], ace[2])
            win32security.SetNamedSecurityInfo(str(leaf), 1, 4, None, None, different, None)
            changed = True
        return result
    monkeypatch.setattr(durable_state, '_verify_copy_bytes', verify)
    entered = False
    try:
        with pytest.raises(msi.ProvenanceConflict):
            with msi.verified_foundation_bytes(expected, root, allow_execution_metadata=True):
                entered = True
        assert not entered, 'changed security must be rejected before any companion launch'
    finally:
        win32security.SetNamedSecurityInfo(str(leaf), 1, 4, None, None, original_security.GetSecurityDescriptorDacl(), None)
