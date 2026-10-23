"""An interrupted native script must restore its exact captured root metadata."""
from copy import deepcopy
import os

import pytest

from pc_agent.platform.windows import durable_state, installer_data_security as data
from pc_agent.tests.windows.test_installer_data_security import operation


@pytest.fixture
def interrupted(operation, monkeypatch):
    paths, request = operation
    # Only the native inheritance bookkeeping bit differs; the complete ACL
    # bytes, namespace identities and all credential-leaf descriptors stay bound.
    descriptor = (b'\x01\x00' + (0x9404).to_bytes(2, 'little') + b'\x00' * 16).hex()
    original = {'root': {'identity': [1, 1], 'descriptor': descriptor},
                'leaves': dict.fromkeys(data._LEAVES)}
    current = deepcopy(original)
    monkeypatch.setattr(data, '_snapshot', lambda _: deepcopy(current))
    data.prepare(paths, request)
    data.enter_native(paths, request)
    current['root']['descriptor'] = (b'\x01\x00' + (0x9004).to_bytes(2, 'little') + b'\x00' * 16).hex()
    recovered = {**request, 'recovery': True, 'session_id': 'ecf28bea-3d44-4455-af9f-57c95b27913c'}
    writes = []
    def restore(_paths, expected, observed):
        assert expected == original and observed == current
        writes.append(True)
        current.clear(); current.update(deepcopy(original))
    monkeypatch.setattr(data, '_restore_native_rollback_descriptor', restore, raising=False)
    return paths, recovered, original, current, writes


def test_native_rollback_restores_exact_descriptor_before_strict_recheck(interrupted):
    paths, request, original, current, writes = interrupted
    with pytest.raises(ValueError, match='PROVENANCE_CONFLICT'):
        data.before_native(paths, request)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        data.restore_native_rollback_inheritance(paths, request)
    assert writes == [True] and current == original
    data.before_native(paths, request)
    assert data._read(paths, request)['phase'] == 'native-entered'


@pytest.mark.parametrize('defect', ['root-identity', 'leaf', 'acl-byte', 'protection', 'added-bit', 'prepared', 'normal-request'])
def test_native_rollback_never_repairs_other_security_changes(interrupted, defect):
    paths, request, original, current, writes = interrupted
    if defect == 'root-identity': current['root']['identity'][1] += 1
    elif defect == 'leaf': current['leaves']['device-credential'] = {'identity': [1, 2], 'descriptor': 'aa'}
    elif defect == 'acl-byte': current['root']['descriptor'] = current['root']['descriptor'][:-2] + '01'
    elif defect in ('protection', 'added-bit'):
        raw = bytearray.fromhex(current['root']['descriptor']); raw[3] ^= 0x10 if defect == 'protection' else 0x02
        current['root']['descriptor'] = raw.hex()
    elif defect == 'prepared':
        record = data._read(paths, request); record['phase'] = 'prepared'; data._write(paths, request, record)
    else: request = {**request, 'recovery': False}
    with durable_state.installer_mutation_checkpoints(lambda: None):
        with pytest.raises(ValueError): data.restore_native_rollback_inheritance(paths, request)
    assert writes == []


def test_native_rollback_requires_live_mutation_authority(interrupted):
    paths, request, _, _, writes = interrupted
    with pytest.raises(ValueError, match='installer mutation scope'):
        data.restore_native_rollback_inheritance(paths, request)
    assert not writes


def test_native_rollback_does_not_accept_unsuccessful_restoration(interrupted, monkeypatch):
    paths, request, _, _, _ = interrupted
    monkeypatch.setattr(data, '_restore_native_rollback_descriptor', lambda *_: None)
    with durable_state.installer_mutation_checkpoints(lambda: None):
        with pytest.raises(ValueError, match='PROVENANCE_CONFLICT'):
            data.restore_native_rollback_inheritance(paths, request)


@pytest.mark.skipif(os.name != 'nt', reason='native security descriptor persistence')
def test_native_restore_keeps_child_acl_bytes_and_directory_identity(tmp_path, monkeypatch):
    import win32security as security
    root = tmp_path / 'root'; root.mkdir()
    dacl = security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)', 1).GetSecurityDescriptorDacl()
    security.SetNamedSecurityInfo(str(root), security.SE_FILE_OBJECT,
        security.DACL_SECURITY_INFORMATION | security.PROTECTED_DACL_SECURITY_INFORMATION,
        None, None, dacl, None)
    flags = security.OWNER_SECURITY_INFORMATION | security.GROUP_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION
    read = lambda path: security.GetNamedSecurityInfo(str(path), security.SE_FILE_OBJECT, flags)
    original = read(root); child = root / 'child'; child.write_bytes(b'native test fixture')
    child_before = bytes(read(child)); identity = root.stat()
    stripped = security.SECURITY_DESCRIPTOR(bytes(original)); stripped.SetSecurityDescriptorControl(0x400, 0)
    security.SetFileSecurity(str(root), security.DACL_SECURITY_INFORMATION, stripped)
    observed = read(root)
    assert original.GetSecurityDescriptorControl()[0] ^ observed.GetSecurityDescriptorControl()[0] == 0x400
    expected = {'root': {'identity': [identity.st_dev, identity.st_ino], 'descriptor': bytes(original).hex()}, 'leaves': {}}
    current = {'root': {**expected['root'], 'descriptor': bytes(observed).hex()}, 'leaves': {}}
    monkeypatch.setattr(data, '_root', lambda _: root)
    monkeypatch.setattr(data, '_snapshot', lambda _: current)
    def lost_owner():
        raise ValueError('OWNER_AUTH_FAILED')
    with durable_state.installer_mutation_checkpoints(lost_owner):
        with pytest.raises(ValueError, match='OWNER_AUTH_FAILED'):
            data._restore_native_rollback_descriptor(None, expected, current)
    assert bytes(read(root)) == bytes(observed) and bytes(read(child)) == child_before
    rename_blocked = []
    def live_owner():
        with pytest.raises(PermissionError): root.rename(tmp_path / 'replaced-root')
        rename_blocked.append(True)
    with durable_state.installer_mutation_checkpoints(live_owner):
        data._restore_native_rollback_descriptor(None, expected, current)
    assert rename_blocked == [True]
    assert bytes(read(root)) == bytes(original)
    assert bytes(read(child)) == child_before
    assert (root.stat().st_dev, root.stat().st_ino) == (identity.st_dev, identity.st_ino)
