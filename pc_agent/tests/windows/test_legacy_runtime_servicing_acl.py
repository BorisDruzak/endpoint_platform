"""Servicing ACL admission is confined to authenticated original MSI runtime."""
import json,os
from types import SimpleNamespace
import pytest
from pc_agent.platform.windows import legacy_foundation_upgrade as legacy
from pc_agent.platform.windows import msi_inventory as msi,installer_fence as fence
from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
from pc_agent.platform.windows.runtime_identity import _LEGACY_MSI_CONTRACTS

pytestmark=pytest.mark.skipif(os.name!='nt',reason='native Windows ACLs')
TI='S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'

@pytest.fixture
def original_runtime(tmp_path,monkeypatch):
 paths=WindowsUpdatePaths(tmp_path/'Agent',tmp_path/'data/updates/pending_update.json')
 digest=next(iter(_LEGACY_MSI_CONTRACTS));contract=_LEGACY_MSI_CONTRACTS[digest]
 package=SimpleNamespace(sha256=digest,version=contract['version'],product_code=legacy._PRODUCTS[digest])
 root=paths.versions_root/package.version;root.mkdir(parents=True)
 (root/'core.exe').write_bytes(b'original')
 marker={'schema_version':1,'version':package.version,'component_guid':contract['component_guid']}
 (root/'.endpoint-msi-runtime.json').write_text(json.dumps(marker))
 monkeypatch.setattr(legacy,'verify_registration',lambda *_a,**_k:None)
 monkeypatch.setattr(fence,'assert_namespace_security',lambda *_:None)
 return paths,package,root,marker

@pytest.mark.parametrize('writer,flags,allowed',[(TI,0,True),('S-1-3-0',8,True),('S-1-3-0',0,False),('S-1-5-19',0,False),('S-1-5-32-545',0,False)])
def test_exact_legacy_marker_requires_servicing_only_effective_writers(original_runtime,monkeypatch,writer,flags,allowed):
 import win32security as security
 paths,package,root,marker=original_runtime
 acl=security.ACL();acl.AddAccessAllowedAceEx(security.ACL_REVISION,flags,0x10000000,security.ConvertStringSidToSid(writer))
 sd=security.SECURITY_DESCRIPTOR();sd.SetSecurityDescriptorOwner(security.ConvertStringSidToSid('S-1-5-18'),False);sd.SetSecurityDescriptorDacl(True,acl,False)
 monkeypatch.setattr(security,'GetNamedSecurityInfo',lambda *_:sd)
 before={p:p.read_bytes() for p in root.rglob('*') if p.is_file()}
 if allowed:assert json.loads(legacy.read_runtime_marker(paths,package))==marker
 else:
  with pytest.raises(msi.ProvenanceConflict):legacy.read_runtime_marker(paths,package)
 assert before=={p:p.read_bytes() for p in root.rglob('*') if p.is_file()}

@pytest.mark.parametrize('defect',['unknown-package','wrong-version','wrong-product','namespace','native-owner','marker'])
def test_legacy_acl_exception_never_admits_unbound_runtime(original_runtime,monkeypatch,defect):
 paths,package,root,marker=original_runtime
 monkeypatch.setattr(msi,'_assert_registered_cache_security',lambda *_:None)
 if defect=='unknown-package':package.sha256='0'*64
 elif defect=='wrong-version':package.version='3.2.97'
 elif defect=='wrong-product':package.product_code='{11111111-1111-4111-8111-111111111111}'
 elif defect=='namespace':monkeypatch.setattr(fence,'assert_namespace_security',lambda *_:(_ for _ in ()).throw(ValueError('parent writer')))
 elif defect=='native-owner':monkeypatch.setattr(legacy,'verify_registration',lambda *_a,**_k:(_ for _ in ()).throw(msi.ProvenanceConflict()))
 elif defect=='marker':(root/'.endpoint-msi-runtime.json').write_text(json.dumps({**marker,'component_guid':'bad'}))
 with pytest.raises(msi.ProvenanceConflict):legacy.read_runtime_marker(paths,package)

def test_modern_update_state_still_rejects_servicing_writer(monkeypatch):
 import win32security as security
 from pc_agent.platform.windows import update_transaction
 acl=security.ACL();acl.AddAccessAllowedAce(security.ACL_REVISION,0x1f01ff,security.ConvertStringSidToSid(TI))
 sd=security.SECURITY_DESCRIPTOR();sd.SetSecurityDescriptorOwner(security.ConvertStringSidToSid('S-1-5-18'),False);sd.SetSecurityDescriptorDacl(True,acl,False)
 monkeypatch.setattr(security,'GetNamedSecurityInfo',lambda *_:sd)
 with pytest.raises(ValueError,match='unrelated writer'):update_transaction._assert_state_security('unused')


@pytest.mark.parametrize('defect',['nested-directory-writer','nested-file-writer','hardlink','marker-size','marker-mutation'])
def test_legacy_reader_checks_every_source_leaf_and_pinned_marker(original_runtime,monkeypatch,defect):
 from contextlib import contextmanager
 from pc_agent.platform.windows import durable_state
 paths,package,root,marker=original_runtime
 nested=root/'nested';nested.mkdir();leaf=nested/'library.dll';leaf.write_bytes(b'original library')
 def security(path):
  if ((defect=='nested-directory-writer' and path==nested)
      or (defect=='nested-file-writer' and path==leaf)):raise msi.ProvenanceConflict()
 monkeypatch.setattr(msi,'_assert_registered_cache_security',security)
 if defect=='hardlink':os.link(leaf,root/'alias.dll')
 elif defect=='marker-size':(root/'.endpoint-msi-runtime.json').write_bytes(b'x'*4097)
 elif defect=='marker-mutation':
  original=durable_state._pinned_copy_source
  @contextmanager
  def pin(path):
   with original(path) as handle:
    # Simulate a handle/path identity change at the native boundary.
    opened=os.fstat(handle)
    original_fstat=os.fstat
    def fstat(descriptor):
     result=original_fstat(descriptor)
     if descriptor==handle:
      return SimpleNamespace(st_dev=result.st_dev,st_ino=result.st_ino,st_size=result.st_size+1,
       st_mtime_ns=result.st_mtime_ns,st_ctime_ns=opened.st_ctime_ns,st_birthtime_ns=result.st_birthtime_ns,
       st_mode=result.st_mode,st_nlink=result.st_nlink,st_file_attributes=result.st_file_attributes)
     return result
    monkeypatch.setattr(os,'fstat',fstat)
    yield handle
  monkeypatch.setattr(durable_state,'_pinned_copy_source',pin)
 with pytest.raises(msi.ProvenanceConflict):legacy.read_runtime_marker(paths,package)
