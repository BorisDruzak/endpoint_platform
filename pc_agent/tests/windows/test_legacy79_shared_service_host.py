"""Original79 SCM admission uses native registration and a pinned exact host.

MSI inventory is modeled; Windows file handles and file/link checks are real.
"""
import hashlib
import json
import os
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import legacy_foundation_upgrade as legacy
from pc_agent.platform.windows import msi_inventory as msi, installation_provenance as provenance

SHA79='2f7d778799f1e32645af7936dfaf3f090d6ad4df5bb883827ea8a0a5d859f72a'
CODE79='{0FFBDA26-8617-4F9E-A378-833F01048360}'


@pytest.fixture
def machine(tmp_path,monkeypatch):
    security=pytest.importorskip('win32security',reason='native Windows deny-write/delete pin')
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths=WindowsUpdatePaths(tmp_path/'Agent',tmp_path/'data/updates/pending_update.json')
    paths.install_root.mkdir()
    host=paths.install_root/'endpoint-agent-service.exe';host.write_bytes(b'original host')
    package=SimpleNamespace(sha256=SHA79,product_code=CODE79,version='3.2.79',package_code='{11111111-1111-4111-8111-111111111111}')
    release=legacy._runtime_release(package)
    cache=paths.updates_root.parent/'installer-cache';cache.mkdir(parents=True)
    record={'schema_version':'endpoint_windows_installer_provenance_v1',
        'release_manifest_schema_version':release['schema_version'],
        **{key:value for key,value in release.items() if key!='schema_version'},
        'cache_file':f'msi-{SHA79}/EndpointAgent.msi'}
    receipt=cache/'installer-provenance.json';receipt.write_text(json.dumps(record))
    calls=[]
    monkeypatch.setattr(provenance,'_assert_security',lambda *_:None)
    monkeypatch.setattr(msi,'read_package',lambda *_:package)
    monkeypatch.setattr(msi,'verify_foundation',lambda *_a,**_k:calls.append('foundation'))
    monkeypatch.setattr(msi,'verify_registered_cache',lambda *_a,**_k:calls.append('cache'))
    monkeypatch.setattr(legacy,'_SHARED79_HOST_SIZE',len(b'original host'),raising=False)
    monkeypatch.setattr(legacy,'_SHARED79_HOST_SHA256',hashlib.sha256(b'original host').hexdigest(),raising=False)
    class Native:
        defect=None
        def product(self,_):return -1 if self.defect=='absent' else 5
        def property(self,_,name):return {'AssignmentType':'1','PackageCode':package.package_code,'VersionString':package.version}[name]
        def product_metadata(self,*_):return 'foreign' if self.defect=='transform' else ''
        def has_patches(self,*_):return self.defect=='patch'
        def related_products(self,*_):return (package.product_code,'foreign') if self.defect=='foreign' else (package.product_code,)
    native=Native();monkeypatch.setattr(legacy,'NativeMsi',lambda:native)
    sd=security.ConvertStringSecurityDescriptorToSecurityDescriptor('O:SYG:SYD:(A;;FA;;;SY)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;GRGX;;;BU)',1)
    monkeypatch.setattr(security,'GetNamedSecurityInfo',lambda *_:sd)
    return paths,host,package,record,receipt,native,calls


def test_shared_host_identity_is_from_original79_cabinet():
    assert legacy._SHARED79_HOST_SIZE==34094212
    assert legacy._SHARED79_HOST_SHA256=='6100c2351bd65827b4c16b1f7fb77a0007ca9ca192bc512f1642797e62182b11'


def test_native_shared_host_pin_prevents_writes_and_delete_until_context_ends(machine):
    paths,host,package,record,receipt,native,calls=machine
    with legacy._verified_shared_service_host(paths) as proof:
        proof.check();proof.check()
        assert calls==['foundation','cache']
        with pytest.raises(OSError):host.write_bytes(b'tampered host')
        with pytest.raises(OSError):host.unlink()
    host.unlink()


@pytest.mark.parametrize('defect',['wrong-hash','wrong-source','wrong-product','version81','missing-receipt',
    'transform','patch','foreign','absent','same-size-tamper','hardlink','leaf-writer','ancestor-writer'])
def test_shared_host_proof_rejects_foreign_registration_bytes_or_writers(machine,monkeypatch,defect):
    paths,host,package,record,receipt,native,calls=machine
    if defect=='wrong-hash':record['package_sha256']='0'*64
    elif defect=='wrong-source':record['source_revision']='0'*40
    elif defect=='wrong-product':record['product_code']='{22222222-2222-4222-8222-222222222222}'
    elif defect=='version81':
        package.sha256='ad4dc49703513d6dee6fd3e51ac94a09c5967112d58aed4e60a63cf6966251f5'
        package.product_code='{5E140EED-6A05-4D9B-98C6-BCC178C6EC71}';package.version='3.2.81'
        release=legacy._runtime_release(package)
        record.update({key:value for key,value in release.items() if key!='schema_version'})
        record['cache_file']=f'msi-{package.sha256}/EndpointAgent.msi'
        # Valid81 native/cache evidence still must not authorize a shared host.
    elif defect in {'transform','patch','foreign','absent'}:native.defect=defect
    elif defect=='same-size-tamper':host.write_bytes(b'tampered host')
    elif defect=='hardlink':os.link(host,host.parent/'alias.exe')
    elif defect=='leaf-writer':
        import win32security as security
        good=security.GetNamedSecurityInfo
        bad=security.ConvertStringSecurityDescriptorToSecurityDescriptor('O:SYG:SYD:(A;;FA;;;BU)',1)
        monkeypatch.setattr(security,'GetNamedSecurityInfo',lambda path,*args:bad if path==str(host) else good(path,*args))
    elif defect=='ancestor-writer':
        from pc_agent.platform.windows import installer_fence
        monkeypatch.setattr(installer_fence,'assert_namespace_security',lambda *_:(_ for _ in ()).throw(ValueError('unsafe namespace')))
    receipt.write_text(json.dumps(record))
    if defect=='missing-receipt':receipt.unlink()
    with pytest.raises(ValueError):
        with legacy._verified_shared_service_host(paths):pytest.fail('untrusted host admitted')


@pytest.mark.parametrize('defect',['transform','patch','foreign','absent'])
def test_cached_proof_rechecks_registration_at_every_snapshot(machine,defect):
    paths,host,package,record,receipt,native,calls=machine
    with legacy._verified_shared_service_host(paths) as proof:
        native.defect=defect
        with pytest.raises(ValueError):proof.check()
    # A rejected check must still release the Windows handle.
    host.unlink()


def test_failed_byte_check_releases_pin(machine):
    paths,host,*_=machine
    host.write_bytes(b'tampered host')
    with pytest.raises(ValueError):
        with legacy._verified_shared_service_host(paths):pass
    host.unlink()


def test_caller_failure_is_preserved_and_pin_released(machine):
    paths,host,*_=machine
    error=ValueError('UPDATE_IN_PROGRESS')
    with pytest.raises(ValueError) as caught:
        with legacy._verified_shared_service_host(paths):raise error
    assert caught.value is error
    host.unlink()


def test_shared_host_rejects_real_junction_before_opening_host(machine):
    import subprocess
    paths,host,*_=machine
    target=host.parent.parent/'outside';target.mkdir()
    host.rename(target/host.name)
    paths.install_root.rmdir()
    subprocess.run(['cmd.exe','/c','mklink','/J',str(paths.install_root),str(target)],check=True,capture_output=True)
    try:
        with pytest.raises(ValueError):
            with legacy._verified_shared_service_host(paths):pytest.fail('junction admitted')
    finally:os.rmdir(paths.install_root)
    assert (target/host.name).read_bytes()==b'original host'


def test_cached_proof_rechecks_leaf_acl(machine,monkeypatch):
    import win32security as security
    paths,host,*_=machine
    with legacy._verified_shared_service_host(paths) as proof:
        good=security.GetNamedSecurityInfo
        bad=security.ConvertStringSecurityDescriptorToSecurityDescriptor('O:SYG:SYD:(A;;FA;;;BU)',1)
        monkeypatch.setattr(security,'GetNamedSecurityInfo',lambda path,*args:bad if path==str(host) else good(path,*args))
        with pytest.raises(ValueError):proof.check()
    host.unlink()
