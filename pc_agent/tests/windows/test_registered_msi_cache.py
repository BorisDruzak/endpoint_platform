"""Cache comparison supplies evidence only, never a cache execution path."""
from contextlib import contextmanager
import hashlib
import os
from types import SimpleNamespace
import pytest
from pc_agent.platform.windows import msi_inventory as msi

pytestmark=pytest.mark.skipif(os.name!='nt',reason='Windows native cache and security APIs')


@pytest.mark.parametrize('defect', ['none', 'acl', 'registration', 'namespace', 'bytes'])
def test_phase_byte_reuse_keeps_native_registration_and_acl_observations_fresh(tmp_path, monkeypatch, defect):
    import win32api
    from pc_agent.platform.windows import durable_state, installer_fence
    windows = tmp_path / 'Windows'
    cache = windows / 'Installer'
    cache.mkdir(parents=True)
    cached = cache / 'registered.msi'
    cached.write_bytes(b'cached database')
    original = tmp_path / 'source.msi'
    original.write_bytes(b'original database with cabinet')
    package = SimpleNamespace(product_code='product', package_code='package', version='3.2.135',
                              sha256=hashlib.sha256(original.read_bytes()).hexdigest())
    monkeypatch.setattr(win32api, 'GetWindowsDirectory', lambda: str(windows))
    monkeypatch.setattr(msi, 'read_package', lambda *_: package)
    reads, properties, security, namespaces = [], [], [], []
    native = msi.NativeMsi()
    def property_(*_):
        properties.append(True)
        return str(cache / 'different.exe' if len(properties) > 1 and defect == 'registration' else cached)
    monkeypatch.setattr(native, 'property', property_)
    def semantics(path):
        reads.append(path)
        return {'all-tables': 'exact semantic fingerprint'}
    monkeypatch.setattr(native, '_read_database_semantics', semantics)
    def protect(path):
        security.append(path)
        if len(properties) > 1 and defect == 'acl':
            raise msi.ProvenanceConflict()
    monkeypatch.setattr(msi, '_assert_registered_cache_security', protect)
    def namespace(path):
        namespaces.append(path)
        if len(properties) > 1 and defect == 'namespace':
            raise ValueError('namespace changed')
    monkeypatch.setattr(installer_fence, 'assert_namespace_security', namespace)
    with msi.package_read_scope(), durable_state.installer_mutation_checkpoints(lambda: None):
        msi.verify_registered_cache(original, package, native=native)
        if defect == 'bytes':
            durable_state.installer_mutation_checkpoint(required=True)
            original.write_bytes(b'changed canonical package')
        if defect == 'none':
            msi.verify_registered_cache(original, package, native=native)
            assert reads == [original, cached]
            assert security == [windows, cache, cached] * 4
            assert namespaces == [cached] * 4
        else:
            with pytest.raises(msi.ProvenanceConflict):
                msi.verify_registered_cache(original, package, native=native)
    assert len(properties) == 2


@pytest.mark.parametrize('defect',[None,'outside','nested','suffix','ads','ancestor-security','semantic','summary','canonical-bytes','cache-security','cache-mutation'])
def test_registered_cache_requires_protected_pinned_exact_semantics(tmp_path,monkeypatch,defect):
    import win32api
    from pc_agent.platform.windows import durable_state
    from pc_agent.platform.windows import installer_fence
    windows=tmp_path/'Windows';cache=windows/'Installer';cache.mkdir(parents=True)
    path=cache/'registered.msi';path.write_bytes(b'cached-container')
    original=tmp_path/'original.msi';original.write_bytes(b'exact-immutable-media')
    package=SimpleNamespace(product_code='{11111111-1111-4111-8111-111111111111}',
        package_code='{22222222-2222-4222-8222-222222222222}',version='3.2.81',
        sha256=hashlib.sha256(original.read_bytes()).hexdigest())
    monkeypatch.setattr(msi,'read_package',lambda *_:SimpleNamespace(product_code=package.product_code,
        package_code=package.product_code if defect=='summary' else package.package_code,version=package.version))
    monkeypatch.setattr(win32api,'GetWindowsDirectory',lambda:str(windows))
    if defect=='canonical-bytes':original.write_bytes(b'changed')
    registered={'outside':tmp_path/'outside.msi','nested':cache/'nested/file.msi','suffix':cache/'cache.exe','ads':cache/'registered.msi:alternate.msi'}.get(defect,path)
    checked=[];held=set();queried=[]
    def protect(candidate):
        checked.append(candidate)
        if defect=='cache-security' and candidate==path:raise msi.ProvenanceConflict()
    monkeypatch.setattr(msi,'_assert_registered_cache_security',protect,raising=False)
    namespaces=[]
    def namespace(candidate):
        namespaces.append(candidate)
        if defect=='ancestor-security':raise ValueError('UPDATE_STATE_INVALID')
    monkeypatch.setattr(installer_fence,'assert_namespace_security',namespace,raising=False)
    @contextmanager
    def pin(candidate):
        with candidate.open('rb') as stream:
            held.add(candidate)
            try:yield stream.fileno()
            finally:held.remove(candidate)
    monkeypatch.setattr(durable_state,'_pinned_copy_source',pin)
    class Native:
        def property(self,code,name):
            assert code==package.product_code and name=='LocalPackage'
            return str(registered)
        def database_semantics(self,candidate):
            assert held=={path,original}
            queried.append(candidate)
            if candidate==path and defect=='cache-mutation':path.write_bytes(b'changed-cache')
            return {'CustomAction':'different' if candidate==path and defect=='semantic' else 'same'}
    if defect is None:
        assert msi.verify_registered_cache(original,package,native=Native()) is None
        assert queried==[original,path]
        assert path in checked and cache in checked and windows in checked
        assert namespaces==[path,path]
    else:
        with pytest.raises(msi.ProvenanceConflict):msi.verify_registered_cache(original,package,native=Native())
        if defect in {'outside','nested','suffix','ads','ancestor-security','canonical-bytes','cache-security'}:assert not queried
    assert not held


@pytest.mark.parametrize('owner,writer,allowed',[
 ('S-1-5-18','S-1-5-18',True),('S-1-5-32-544','S-1-5-32-544',True),
 ('S-1-5-19','S-1-5-18',False),('S-1-5-18','S-1-5-19',False),
 ('S-1-5-18','S-1-5-32-545',False),('S-1-5-18','S-1-5-11',False)])
def test_native_cache_rejects_service_or_user_owner_and_writers(monkeypatch,owner,writer,allowed):
    import win32security as security
    dacl=security.ACL()
    dacl.AddAccessAllowedAce(security.ACL_REVISION,0x1f01ff,security.ConvertStringSidToSid(writer))
    sd=security.SECURITY_DESCRIPTOR();sd.SetSecurityDescriptorOwner(security.ConvertStringSidToSid(owner),False)
    sd.SetSecurityDescriptorDacl(True,dacl,False)
    monkeypatch.setattr(security,'GetNamedSecurityInfo',lambda *_:sd)
    if allowed:msi._assert_registered_cache_security('unused')
    else:
        with pytest.raises(msi.ProvenanceConflict):msi._assert_registered_cache_security('unused')


@pytest.mark.parametrize('flags,mask,allowed',[(0,0x10000000,False),(8,0x10000000,True),(0,0x120089,True)])
def test_cache_ancestor_distinguishes_effective_access_and_inherit_only(monkeypatch,flags,mask,allowed):
    import win32security as security
    dacl=security.ACL()
    dacl.AddAccessAllowedAceEx(security.ACL_REVISION,flags,mask,security.ConvertStringSidToSid('S-1-3-0'))
    sd=security.SECURITY_DESCRIPTOR();sd.SetSecurityDescriptorOwner(security.ConvertStringSidToSid('S-1-5-18'),False)
    sd.SetSecurityDescriptorDacl(True,dacl,False)
    monkeypatch.setattr(security,'GetNamedSecurityInfo',lambda *_:sd)
    if allowed:msi._assert_registered_cache_security('unused')
    else:
        with pytest.raises(msi.ProvenanceConflict):msi._assert_registered_cache_security('unused')


@pytest.mark.parametrize('mask,flags,allowed',[(4,0,True),(0x40,0,False),(0x10000,0,False),
    (0x40000,0,False),(0x80000,0,False),(0x10000000,0,False),(0x10000000,8,True)])
def test_volume_ancestor_allows_creation_but_rejects_namespace_replacement(tmp_path,monkeypatch,mask,flags,allowed):
    from pathlib import Path
    from pc_agent.platform.windows import installer_fence
    import win32security as security
    target=tmp_path/'Windows/Installer/readonly-example.msi'
    target.parent.mkdir(parents=True);target.write_bytes(b'namespace-only-probe')
    def descriptor(candidate,*_):
        dacl=security.ACL();dacl.AddAccessAllowedAce(security.ACL_REVISION,0x1f01ff,security.ConvertStringSidToSid('S-1-5-18'))
        if Path(candidate)==Path(target.anchor):
            dacl.AddAccessAllowedAceEx(security.ACL_REVISION,flags,mask,security.ConvertStringSidToSid('S-1-5-11'))
        sd=security.SECURITY_DESCRIPTOR();sd.SetSecurityDescriptorOwner(security.ConvertStringSidToSid('S-1-5-32-544'),False)
        sd.SetSecurityDescriptorDacl(True,dacl,False);return sd
    monkeypatch.setattr(security,'GetNamedSecurityInfo',descriptor)
    if allowed:installer_fence.assert_namespace_security(target)
    else:
        with pytest.raises(ValueError):installer_fence.assert_namespace_security(target)
