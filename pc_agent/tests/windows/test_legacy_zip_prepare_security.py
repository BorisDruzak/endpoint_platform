"""Authenticated preparation must outlive native81 without servicing writers."""
import ctypes
import json
import os
from pathlib import Path
from types import SimpleNamespace
import xml.etree.ElementTree as ET

import pytest

from pc_agent.platform.windows import installation_provenance as provenance
from pc_agent.platform.windows import installer_fence as fence
from pc_agent.platform.windows import legacy_foundation_upgrade as legacy
from pc_agent.platform.windows import durable_state
from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
from pc_agent.tests.windows.test_installation_provenance import zip_core
from pc_agent.tests.windows.test_legacy_foundation_admission import RELEASE, PACKAGE

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='native Windows ACL policy')
TI = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'


@pytest.fixture
def live_zip(tmp_path, monkeypatch):
    import win32security as security
    if not ctypes.windll.shell32.IsUserAnAdmin():
        pytest.skip('protected-owner fixture requires administrator')
    paths = WindowsUpdatePaths(tmp_path/'Agent', tmp_path/'data/updates/pending_update.json')
    root = zip_core(paths, version='3.2.125', minimum='3.2.81')
    (root/'nested').mkdir()
    (root/'nested/dependency.dll').write_bytes(b'independent nested fixture')
    manifest = json.loads((root/provenance.BUNDLE_FILENAME).read_bytes())
    import hashlib
    leaf = root/'nested/dependency.dll'
    manifest['files'].append({'path':'nested/dependency.dll', 'size':leaf.stat().st_size,
        'sha256':hashlib.sha256(leaf.read_bytes()).hexdigest()})
    (root/provenance.BUNDLE_FILENAME).write_text(json.dumps(manifest))
    role = SimpleNamespace(release=dict(RELEASE), package=SimpleNamespace(
        sha256=RELEASE['package_sha256'], version='3.2.81',
        product_code=RELEASE['product_code'], package_code=PACKAGE))
    # Only immutable installed81/cache inventory and the operator temporary
    # namespace are seams. DACL APIs, tree, bytes and strict guards are real.
    monkeypatch.setattr(legacy, '_registered_foundation', lambda actual:role)
    monkeypatch.setattr(legacy, 'verify_registration', lambda *args:None)
    monkeypatch.setattr(fence, 'assert_namespace_security', lambda path:None)
    def apply(path, sddl):
        sd = security.ConvertStringSecurityDescriptorToSecurityDescriptor('O:BAG:BA'+sddl, 1)
        security.SetNamedSecurityInfo(str(path), security.SE_FILE_OBJECT,
            security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION
            | security.PROTECTED_DACL_SECURITY_INFORMATION,
            sd.GetSecurityDescriptorOwner(), None, sd.GetSecurityDescriptorDacl(), None)
    for directory in (root, root/'nested'):
        apply(directory, f'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{TI})(A;OICIIO;GA;;;CO)')
    for leaf in root.rglob('*'):
        if leaf.is_file():apply(leaf, 'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;BU)')
    apply(paths.current_path, 'D:P(A;;FA;;;SY)(A;;FA;;;BA)')
    evidence = provenance.inspect_installed_core(paths, resulting_foundation='3.2.114')
    request = {'selected':evidence.current.digest, 'previous':None,
        'release':{'version':'3.2.114'}}
    data = paths.pending_path.parent.parent
    data.mkdir(parents=True)
    for name in ('identity.json','device.json','credentials.json','enrollment.json'):
        (data/name).write_bytes(('private fixture '+name).encode())
    return paths, root, role, request, evidence, apply


def test_prepared_zip_survives_original_native_owner_removal(live_zip, monkeypatch):
    import win32security as security
    paths, root, role, request, evidence, apply = live_zip
    before = {p:p.read_bytes() for p in paths.install_root.rglob('*') if p.is_file()}
    selector_sd = bytes(security.GetFileSecurity(str(paths.current_path), 7))
    data = paths.pending_path.parent.parent
    private = {p:(p.read_bytes() if p.is_file() else None, bytes(security.GetFileSecurity(str(p), 7)))
        for p in (data, *data.iterdir())}
    with durable_state.installer_mutation_checkpoints(lambda:None):
        legacy._prepare_zip_payload_security(paths, request, role)
    monkeypatch.setattr(legacy, '_registered_foundation', lambda actual:None)
    assert provenance.inspect_installed_core(paths, resulting_foundation='3.2.114') == evidence
    assert before == {p:p.read_bytes() for p in paths.install_root.rglob('*') if p.is_file()}
    assert bytes(security.GetFileSecurity(str(paths.current_path), 7)) == selector_sd
    assert private == {p:(p.read_bytes() if p.is_file() else None, bytes(security.GetFileSecurity(str(p), 7))) for p in private}
    namespace = {'w':'http://wixtoolset.org/schemas/v4/wxs'}
    wxs = Path(__file__).resolve().parents[3]/'packaging/windows/wix/Components.wxs'
    policies = ET.parse(wxs).findall('.//w:CreateFolder/w:PermissionEx', namespace)
    expected = security.ConvertStringSecurityDescriptorToSecurityDescriptor(policies[0].get('Sddl'), 1)
    for path in (root, *root.rglob('*')):
        provenance._assert_security(path)
        sd = security.GetNamedSecurityInfo(str(path), security.SE_FILE_OBJECT, 7)
        actual = sd.GetSecurityDescriptorDacl()
        wanted = expected.GetSecurityDescriptorDacl()
        assert actual.GetAceCount() == wanted.GetAceCount() == 5
        assert [(actual.GetAce(i)[1], str(actual.GetAce(i)[2])) for i in range(5)] == [
            (wanted.GetAce(i)[1], str(wanted.GetAce(i)[2])) for i in range(5)]
        assert sd.GetSecurityDescriptorControl()[0] & security.SE_DACL_PROTECTED
        flags = security.OBJECT_INHERIT_ACE | security.CONTAINER_INHERIT_ACE if path.is_dir() else 0
        assert all(actual.GetAce(i)[0][1] == flags for i in range(5))


@pytest.mark.parametrize('defect', ['bytes','leaf-writer','request','native'])
def test_bad_prepared_zip_never_gets_security_repaired(live_zip, monkeypatch, defect):
    import win32security as security
    paths, root, role, request, evidence, apply = live_zip
    if defect == 'bytes':(root/'pc_agent.exe').write_bytes(b'tampered')
    elif defect == 'leaf-writer':apply(root/'pc_agent.exe', f'D:P(A;;FA;;;BA)(A;;FA;;;{TI})')
    elif defect == 'request':request['selected'] = '0'*64
    else:monkeypatch.setattr(legacy, '_registered_foundation', lambda actual:None)
    before = {p:bytes(security.GetFileSecurity(str(p), 7))
        for p in (root, *root.rglob('*'))}
    with durable_state.installer_mutation_checkpoints(lambda:None), pytest.raises(ValueError):
        legacy._prepare_zip_payload_security(paths, request, role)
    assert before == {p:bytes(security.GetFileSecurity(str(p), 7)) for p in before}


def test_partial_security_preparation_can_retry_without_native_or_selector_repair(live_zip):
    paths, root, role, request, evidence, apply = live_zip
    writes = 0
    def interrupt():
        nonlocal writes
        writes += 1
        if writes == 3:raise ValueError('owner lost')
    with durable_state.installer_mutation_checkpoints(interrupt), pytest.raises(ValueError):
        legacy._prepare_zip_payload_security(paths, request, role)
    assert provenance.inspect_installed_core(paths, resulting_foundation='3.2.114') == evidence
    with durable_state.installer_mutation_checkpoints(lambda:None):
        legacy._prepare_zip_payload_security(paths, request, role)
    assert provenance.inspect_installed_core(paths, resulting_foundation='3.2.114') == evidence
    for path in (root, *root.rglob('*')):provenance._assert_security(path)


def test_strict_root_does_not_skip_legacy_nested_directory_on_retry(live_zip):
    paths, root, role, request, evidence, apply = live_zip
    apply(root, 'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)')
    provenance._assert_security(root)
    with pytest.raises(ValueError):provenance._assert_security(root/'nested')
    with durable_state.installer_mutation_checkpoints(lambda:None):
        legacy._prepare_zip_payload_security(paths, request, role)
    for path in (root, *root.rglob('*')):provenance._assert_security(path)


def add_previous_zip(model):
    paths, root, role, request, evidence, apply = model
    current = paths.current_path.read_bytes()
    previous = zip_core(paths, version='3.2.124', minimum='3.2.81')
    paths.previous_path.write_bytes(paths.current_path.read_bytes())
    paths.current_path.write_bytes(current)
    apply(paths.previous_path, 'D:P(A;;FA;;;SY)(A;;FA;;;BA)')
    apply(previous, f'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{TI})')
    for leaf in previous.rglob('*'):
        if leaf.is_file():apply(leaf, 'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;BU)')
    both = provenance.inspect_installed_core(paths, resulting_foundation='3.2.114')
    request['previous'] = both.previous.digest
    return previous, both


def test_previous_zip_is_also_strict_after_native_owner_removal(live_zip, monkeypatch):
    paths, root, role, request, evidence, apply = live_zip
    previous, both = add_previous_zip(live_zip)
    with durable_state.installer_mutation_checkpoints(lambda:None):
        legacy._prepare_zip_payload_security(paths, request, role)
    monkeypatch.setattr(legacy, '_registered_foundation', lambda actual:None)
    assert provenance.inspect_installed_core(paths, resulting_foundation='3.2.114') == both
    for tree in (root, previous):
        for path in (tree, *tree.rglob('*')):provenance._assert_security(path)


def test_late_previous_zip_acl_change_cannot_escape_current_tree_closure(live_zip):
    import win32security as security
    paths, root, role, request, evidence, apply = live_zip
    previous, both = add_previous_zip(live_zip)
    writes = sum(1 + len(tuple(tree.rglob('*'))) for tree in (root, previous))
    checkpoints = 0
    def corrupt_completed_current():
        nonlocal checkpoints
        checkpoints += 1
        if checkpoints == writes + 1:
            target = root/'nested'
            acl = security.GetFileSecurity(str(target), 4).GetSecurityDescriptorDacl()
            acl.AddAccessAllowedAce(security.ACL_REVISION, 2, security.ConvertStringSidToSid('S-1-5-32-545'))
            security.SetNamedSecurityInfo(str(target), security.SE_FILE_OBJECT, 4, None, None, acl, None)
    with durable_state.installer_mutation_checkpoints(corrupt_completed_current), pytest.raises(ValueError):
        legacy._prepare_zip_payload_security(paths, request, role)


def test_zip_normalization_requires_active_installer_mutation_scope(live_zip):
    paths, root, role, request, evidence, apply = live_zip
    with pytest.raises(ValueError):
        legacy._prepare_zip_payload_security(paths, request, role)


@pytest.mark.parametrize('predecessor', [None, SimpleNamespace(package=SimpleNamespace(sha256='0'*64))])
def test_other_foundations_do_not_acquire_zip_mutation(predecessor, monkeypatch):
    monkeypatch.setattr(legacy, '_registered_foundation', lambda *args:pytest.fail('unexpected legacy inventory'))
    legacy._prepare_zip_payload_security(None, {}, predecessor)


def test_admitted_trustedinstaller_owner_becomes_canonical_administrators(live_zip):
    import win32api
    import win32security as security
    paths, root, role, request, evidence, apply = live_zip
    token = security.OpenProcessToken(win32api.GetCurrentProcess(), 0x28)
    privilege = security.LookupPrivilegeValue(None, 'SeRestorePrivilege')
    previous = security.AdjustTokenPrivileges(token, False, [(privilege,2)])
    try:
        security.SetNamedSecurityInfo(str(root), security.SE_FILE_OBJECT,
            security.OWNER_SECURITY_INFORMATION, security.ConvertStringSidToSid(TI), None, None, None)
    finally:
        security.AdjustTokenPrivileges(token, False, previous)
        token.Close()
    with durable_state.installer_mutation_checkpoints(lambda:None):
        legacy._prepare_zip_payload_security(paths, request, role)
    assert security.ConvertSidToStringSid(security.GetFileSecurity(str(root),1).GetSecurityDescriptorOwner()) == 'S-1-5-32-544'
    assert provenance.inspect_installed_core(paths, resulting_foundation='3.2.114') == evidence


@pytest.mark.parametrize('target', ['nested','nested/dependency.dll'])
def test_every_nested_object_is_pinned_before_first_acl_change(live_zip, target):
    import win32security as security
    paths, root, role, request, evidence, apply = live_zip
    outside = paths.install_root/'outside';outside.mkdir()
    before = bytes(security.GetFileSecurity(str(outside), 7))
    checkpoints = 0
    def replace():
        nonlocal checkpoints
        checkpoints += 1
        if checkpoints == 1:return  # Entry authority check precedes pinning.
        with pytest.raises(OSError):
            (root/target).rename(outside/'replacement')
        raise ValueError('stop after pin check')
    with durable_state.installer_mutation_checkpoints(replace), pytest.raises(ValueError):
        legacy._prepare_zip_payload_security(paths, request, role)
    assert bytes(security.GetFileSecurity(str(outside), 7)) == before
    assert (root/target).exists()


@pytest.mark.parametrize('late', [False, True])
def test_acl_changes_during_preparation_cannot_be_erased_or_escape_final_check(live_zip, late):
    import win32security as security
    paths, root, role, request, evidence, apply = live_zip
    checkpoints = 0
    def change_acl():
        nonlocal checkpoints
        checkpoints += 1
        # Early: poison the root immediately before its setter. Late: poison
        # the completed nested directory immediately before the final setter.
        if late:
            trigger = len(tuple(root.rglob('*'))) + 2
            target = root/'nested'
        else:
            trigger = 2
            target = root
        if checkpoints == trigger:
            sd = security.GetNamedSecurityInfo(str(target), security.SE_FILE_OBJECT, 4)
            acl = sd.GetSecurityDescriptorDacl()
            acl.AddAccessAllowedAce(security.ACL_REVISION, 2, security.ConvertStringSidToSid('S-1-5-32-545'))
            security.SetNamedSecurityInfo(str(target), security.SE_FILE_OBJECT, 4, None, None, acl, None)
    with durable_state.installer_mutation_checkpoints(change_acl), pytest.raises(ValueError):
        legacy._prepare_zip_payload_security(paths, request, role)


@pytest.mark.parametrize('sid', ['S-1-5-32-545',
    'S-1-5-80-1102781572-1373263041-1070489469-7526906-1468061691',
    'S-1-5-80-327494974-20047353-929432329-1920152597-707704661'])
def test_normalized_payload_allows_read_execute_but_no_reader_mutation(live_zip, sid):
    from ctypes import wintypes
    import win32api
    import win32security as security
    paths, root, role, request, evidence, apply = live_zip
    with durable_state.installer_mutation_checkpoints(lambda:None):
        legacy._prepare_zip_payload_security(paths, request, role)
    class Mapping(ctypes.Structure):
        _fields_ = [('read',wintypes.DWORD),('write',wintypes.DWORD),
            ('execute',wintypes.DWORD),('all',wintypes.DWORD)]
    check = ctypes.WinDLL('advapi32', use_last_error=True).AccessCheck
    check.argtypes = [ctypes.c_void_p, wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(Mapping),
        ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.BOOL)]
    check.restype = wintypes.BOOL
    token = security.OpenProcessToken(win32api.GetCurrentProcess(), 0xa)
    restricted = security.CreateRestrictedToken(token, 1, None, None, [(security.ConvertStringSidToSid(sid),0)])
    impersonation = security.DuplicateToken(restricted, security.SecurityImpersonation)
    try:
        for path in (root, root/'nested', root/'nested/dependency.dll', root/'pc_agent.exe'):
            sd = ctypes.create_string_buffer(bytes(security.GetFileSecurity(str(path), 7)))
            mapping = Mapping(0x120089,0x120116,0x1200a9,0x1f01ff)
            for desired, allowed in ((0x1200a9,True),(2,False),(4,False),(0x40,False),
                (0x10000,False),(0x40000,False),(0x80000,False)):
                privileges = ctypes.create_string_buffer(1024)
                size, granted, status = wintypes.DWORD(1024), wintypes.DWORD(), wintypes.BOOL()
                assert check(sd, int(impersonation), desired, ctypes.byref(mapping), privileges,
                    ctypes.byref(size), ctypes.byref(granted), ctypes.byref(status)), ctypes.get_last_error()
                assert bool(status.value) == allowed, (path.name, desired, granted.value)
    finally:
        impersonation.Close();restricted.Close();token.Close()
