"""A native81-published ZIP keeps exact bytes without widening state writers."""
import hashlib
import json
import os
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import installation_provenance as provenance
from pc_agent.platform.windows import installer_fence as fence
from pc_agent.platform.windows import legacy_foundation_upgrade as legacy
from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
from pc_agent.tests.windows.test_legacy_foundation_admission import RELEASE, PACKAGE

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='native Windows ACL policy')
TI = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
_registered_foundation = legacy._registered_foundation
_verify_registration = legacy.verify_registration


def descriptor(aces, owner='S-1-5-18'):
    import win32security as security
    acl = security.ACL()
    for sid, flags, mask in aces:
        acl.AddAccessAllowedAceEx(security.ACL_REVISION, flags, mask,
            security.ConvertStringSidToSid(sid))
    sd = security.SECURITY_DESCRIPTOR()
    sd.SetSecurityDescriptorOwner(security.ConvertStringSidToSid(owner), False)
    sd.SetSecurityDescriptorDacl(True, acl, False)
    return sd


@pytest.fixture
def installed_zip(tmp_path, monkeypatch):
    import win32security as security
    paths = WindowsUpdatePaths(tmp_path/'Agent', tmp_path/'data/updates/pending_update.json')
    root = paths.versions_root/'3.2.125'
    (root/'_internal').mkdir(parents=True)
    (root/'pc_agent.exe').write_bytes(b'exact frozen core')
    (root/'_internal/payload.bin').write_bytes(b'exact nested dependency')
    (root/'endpoint-runtime-contract.json').write_text(json.dumps({
        'schema_version':1, 'version':'3.2.125', 'source_revision':'a'*40,
        'minimum_launcher_version':'3.2.81'}))
    manifest = {'schema_version':1, 'version':'3.2.125', 'source_revision':'a'*40,
        'files':[{'path':p.relative_to(root).as_posix(), 'size':p.stat().st_size,
            'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
            for p in sorted(root.rglob('*')) if p.is_file()]}
    (root/provenance.BUNDLE_FILENAME).write_text(json.dumps(manifest))
    (root/provenance.ZIP_RECEIPT).write_text(json.dumps({
        'version':'3.2.125', 'sha256':'b'*64, 'size':1234}))
    paths.current_path.write_text(json.dumps({'schema_version':1,
        'version':'3.2.125', 'source_revision':'a'*40}))
    role = SimpleNamespace(release=dict(RELEASE), package=SimpleNamespace(
        sha256=RELEASE['package_sha256'], version=RELEASE['version'],
        product_code=RELEASE['product_code'], package_code=PACKAGE))
    monkeypatch.setattr(legacy, '_registered_foundation', lambda actual:role)
    checked = []
    monkeypatch.setattr(legacy, 'verify_registration', lambda package, release:
        checked.append((package, release)))
    monkeypatch.setattr(fence, 'assert_namespace_security', lambda path:None)
    directories = descriptor([(TI,0,0x1f01ff), ('S-1-3-0',8,0x10000000)])
    leaves = descriptor([('S-1-5-18',0,0x1f01ff), ('S-1-5-32-544',0,0x1f01ff)])
    overrides = {}
    monkeypatch.setattr(security, 'GetNamedSecurityInfo', lambda path,*args:
        overrides.get(str(path), directories if os.path.isdir(path) else leaves))
    return paths, root, role, overrides, checked


def test_exact_native81_zip_with_servicing_directories_is_read_only(installed_zip):
    paths, root, role, overrides, checked = installed_zip
    before = {p:p.read_bytes() for p in paths.install_root.rglob('*') if p.is_file()}
    inspected = provenance.inspect_installed_core(paths, resulting_foundation='3.2.113')
    assert inspected.current.origin == 'zip'
    assert inspected.current.identity.version == '3.2.125'
    assert inspected.current.identity.minimum_launcher_version == '3.2.81'
    assert checked == [(role.package, role.release)]
    assert before == {p:p.read_bytes() for p in paths.install_root.rglob('*') if p.is_file()}


@pytest.mark.parametrize('defect', ['absent-native','foreign-native','native-change',
    'root-users','nested-users','effective-creator','leaf-ti','receipt-ti','manifest-ti',
    'selector-ti','null-dacl','untrusted-owner','ancestor','hardlink',
    'changed-bytes','extra','missing','manifest-source','receipt-version'])
def test_legacy_zip_exception_keeps_ownership_acl_and_payload_guards(installed_zip, monkeypatch, defect):
    paths, root, role, overrides, checked = installed_zip
    if defect == 'absent-native':
        monkeypatch.setattr(legacy, '_registered_foundation', lambda actual:None)
    elif defect == 'foreign-native':
        role.release['package_sha256'] = '0'*64
    elif defect == 'native-change':
        monkeypatch.setattr(legacy, 'verify_registration', lambda *args:
            (_ for _ in ()).throw(legacy.ProvenanceConflict()))
    elif defect in {'root-users','nested-users','effective-creator','leaf-ti','receipt-ti','manifest-ti','selector-ti'}:
        target = {'root-users':root, 'nested-users':root/'_internal', 'effective-creator':root,
            'leaf-ti':root/'pc_agent.exe', 'receipt-ti':root/provenance.ZIP_RECEIPT,
            'manifest-ti':root/provenance.BUNDLE_FILENAME, 'selector-ti':paths.current_path}[defect]
        sid = 'S-1-3-0' if defect == 'effective-creator' else TI if defect.endswith('-ti') else 'S-1-5-32-545'
        overrides[str(target)] = descriptor([(sid,0,0x1f01ff)])
    elif defect == 'null-dacl':
        sd = descriptor([]); sd.SetSecurityDescriptorDacl(True,None,False)
        overrides[str(root)] = sd
    elif defect == 'untrusted-owner':
        overrides[str(root)] = descriptor([(TI,0,0x1f01ff)], owner='S-1-5-32-545')
    elif defect == 'ancestor':
        monkeypatch.setattr(fence, 'assert_namespace_security', lambda path:
            (_ for _ in ()).throw(ValueError('untrusted ancestor')))
    elif defect == 'hardlink':
        os.link(root/'pc_agent.exe', paths.install_root/'outside-alias')
    elif defect == 'changed-bytes':
        (root/'pc_agent.exe').write_bytes(b'tampered')
    elif defect == 'extra':
        (root/'unknown.dll').write_bytes(b'foreign')
    elif defect == 'missing':
        (root/'pc_agent.exe').unlink()
    elif defect == 'manifest-source':
        manifest = json.loads((root/provenance.BUNDLE_FILENAME).read_bytes())
        manifest['source_revision'] = 'c'*40
        (root/provenance.BUNDLE_FILENAME).write_text(json.dumps(manifest))
    elif defect == 'receipt-version':
        receipt = json.loads((root/provenance.ZIP_RECEIPT).read_bytes())
        receipt['version'] = '3.2.126'
        (root/provenance.ZIP_RECEIPT).write_text(json.dumps(receipt))
    before = {p:p.read_bytes() for p in paths.install_root.rglob('*') if p.is_file()}
    with pytest.raises(ValueError):
        provenance.inspect_installed_core(paths, resulting_foundation='3.2.113')
    assert before == {p:p.read_bytes() for p in paths.install_root.rglob('*') if p.is_file()}


@pytest.mark.parametrize('defect', ['native-change','new-file','leaf-swap','receipt-acl','root-swap'])
def test_full_zip_verification_stays_inside_native_and_tree_recheck(installed_zip, monkeypatch, defect):
    paths, root, role, overrides, checked = installed_zip
    original = provenance._inspect_zip
    def inspect(*args):
        result = original(*args)
        if defect == 'native-change':
            monkeypatch.setattr(legacy, 'verify_registration', lambda *args:
                (_ for _ in ()).throw(legacy.ProvenanceConflict()))
        elif defect == 'new-file':
            (root/'late.dll').write_bytes(b'late mutation')
        elif defect == 'leaf-swap':
            original_leaf = root/'pc_agent.exe'
            original_leaf.rename(root/'renamed.exe')
            original_leaf.write_bytes(b'exact frozen core')
        elif defect == 'receipt-acl':
            overrides[str(root/provenance.ZIP_RECEIPT)] = descriptor([(TI,0,0x1f01ff)])
        elif defect == 'root-swap':
            # The actual held Windows directory handle must reject this rename.
            root.rename(root.with_name('substituted'))
        return result
    monkeypatch.setattr(provenance, '_inspect_zip', inspect)
    with pytest.raises(ValueError):
        provenance.inspect_installed_core(paths, resulting_foundation='3.2.113')


def test_modern_strict_zip_never_uses_legacy_admission(installed_zip, monkeypatch):
    import win32security as security
    paths, root, role, overrides, checked = installed_zip
    strict = descriptor([('S-1-5-18',0,0x1f01ff)])
    monkeypatch.setattr(security, 'GetNamedSecurityInfo', lambda *args:strict)
    monkeypatch.setattr(legacy, '_registered_foundation', lambda paths:
        pytest.fail('a strict ZIP acquired a legacy dependency'))
    assert provenance.inspect_installed_core(paths, resulting_foundation='3.2.113').current.origin == 'zip'


def test_failed_payload_releases_the_owned_directory_pin(installed_zip):
    paths, root, role, overrides, checked = installed_zip
    (root/'pc_agent.exe').write_bytes(b'tampered')
    with pytest.raises(ValueError):
        provenance.inspect_installed_core(paths, resulting_foundation='3.2.113')
    destination = root.with_name('after-refusal')
    root.rename(destination)
    assert destination.is_dir()


def test_nested_junction_cannot_acquire_legacy_zip_admission(installed_zip, tmp_path):
    import subprocess
    paths, root, role, overrides, checked = installed_zip
    outside = tmp_path/'outside'
    outside.mkdir()
    result = subprocess.run(['cmd.exe','/c','mklink','/J',str(root/'junction'),str(outside)],
        capture_output=True, check=False)
    assert result.returncode == 0
    with pytest.raises(ValueError):
        provenance.inspect_installed_core(paths, resulting_foundation='3.2.113')


@pytest.mark.parametrize('defect', ['foundation-feature','component-state','component-keypath','cache'])
def test_full_native_and_cache_admission_is_renewed_after_zip_verification(installed_zip, monkeypatch, tmp_path, defect):
    import win32api
    from pc_agent.platform.windows import msi_inventory as msi, durable_state
    paths, root, role, overrides, checked = installed_zip
    cache = paths.updates_root.parent/'installer-cache'
    media = cache/f"msi-{RELEASE['package_sha256']}/EndpointAgent.msi"
    media.parent.mkdir(parents=True); media.write_bytes(b'original MSI database')
    windows = tmp_path/'Windows'
    registered = windows/'Installer/cached.msi'
    registered.parent.mkdir(parents=True); registered.write_bytes(media.read_bytes())
    record = {'schema_version':'endpoint_windows_installer_provenance_v1',
        'release_manifest_schema_version':RELEASE['schema_version'],
        **{key:value for key,value in RELEASE.items() if key!='schema_version'},
        'cache_file':f"msi-{RELEASE['package_sha256']}/EndpointAgent.msi"}
    (cache/'installer-provenance.json').write_text(json.dumps(record))
    component = msi.Component('foundation', '{11111111-1111-4111-8111-111111111111}',
        'INSTALLFOLDER', 'service', (msi.FOUNDATION_FEATURE,))
    package = msi.PackageInventory(RELEASE['package_sha256'], RELEASE['product_code'], PACKAGE,
        RELEASE['version'], {msi.FOUNDATION_FEATURE:1}, {'foundation':component},
        (msi.InstalledFile('service','foundation','endpoint-agent-service.exe',1),))
    state = {'changed':False}
    class Native:
        def product(self, code):return 5
        def property(self, code, name):
            return {'AssignmentType':'1','PackageCode':PACKAGE,'VersionString':RELEASE['version'],
                'LocalPackage':str(registered)}[name]
        def product_metadata(self, *args):return ''
        def has_patches(self, *args):return False
        def related_products(self, *args):return (RELEASE['product_code'],)
        def feature(self, *args):return 2 if state['changed'] and defect=='foundation-feature' else 3
        def component(self, *args):
            return (2 if state['changed'] and defect=='component-state' else 3,
                str(paths.install_root/('foreign.exe' if state['changed'] and defect=='component-keypath' else 'endpoint-agent-service.exe')))
        def database_semantics(self, path):return path.read_bytes()
    monkeypatch.setattr(legacy, '_registered_foundation', _registered_foundation)
    monkeypatch.setattr(legacy, 'verify_registration', _verify_registration)
    monkeypatch.setattr(legacy, 'NativeMsi', Native)
    monkeypatch.setattr(msi, 'read_package', lambda *args:package)
    monkeypatch.setattr(win32api, 'GetWindowsDirectory', lambda:str(windows))
    # Immutable canonical-media admission is a boundary seam; the real cache
    # comparison and real foundation feature/component checks remain active.
    monkeypatch.setattr(durable_state, '_verify_copy_bytes', lambda *args:None)
    inspect_zip = provenance._inspect_zip
    def inspect(*args):
        result = inspect_zip(*args)
        state['changed'] = True
        if defect == 'cache':registered.write_bytes(b'changed cached MSI semantics')
        return result
    monkeypatch.setattr(provenance, '_inspect_zip', inspect)
    with pytest.raises(ValueError):
        provenance.inspect_installed_core(paths, resulting_foundation='3.2.113')
