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


@pytest.fixture
def retained_reconciliation(original_runtime,monkeypatch):
 import hashlib
 import win32security as security
 from endpoint_contracts.runtime_payload import PayloadFile,PayloadIdentity
 from pc_agent.platform.windows import installation_provenance as provenance,runtime_identity
 paths,package,root,marker=original_runtime
 raw=(root/provenance.MSI_MARKER).read_bytes()
 identity=PayloadIdentity(package.version,'a'*40,None,
  (PayloadFile('core.exe',8,hashlib.sha256(b'original').hexdigest()),))
 retained=SimpleNamespace(identity=identity,record_bytes=b'authenticated archive record',record={
  'package':{'sha256':package.sha256,'product_code':package.product_code},
  'compatibility_foundations':['3.2.82'],'original_marker_bytes':raw.hex(),'original_manifest_bytes':''})
 # The archive/plan parser boundary is modeled; native ACL and surviving-byte
 # checks below remain real. A servicing exception must not become native entry.
 monkeypatch.setattr(runtime_identity,'verify_retained_archive',lambda *_:retained)
 monkeypatch.setattr(legacy,'verify_registration',lambda *_a,**_k:pytest.fail('read-only evidence gained native authority'))
 expected=SimpleNamespace(identity=SimpleNamespace(version='3.2.106',files=()),manifest={},
  package=SimpleNamespace(files=(SimpleNamespace(path='versions/3.2.106/pc_agent.exe',component='core'),),
   components={'core':SimpleNamespace(guid='{33333333-3333-4333-8333-333333333333}')}))
 monkeypatch.setattr(provenance,'_expected_request',lambda _:expected)
 monkeypatch.setattr(provenance,'_read_plan',lambda *_:{'handoff':False,'archives':['a'*64],
  'current_before':None,'current_after':None,'previous_before':None,'previous_after':None})
 acl=security.ACL()
 acl.AddAccessAllowedAceEx(security.ACL_REVISION,0,0x1f01ff,security.ConvertStringSidToSid(TI))
 acl.AddAccessAllowedAceEx(security.ACL_REVISION,8,0x10000000,security.ConvertStringSidToSid('S-1-3-0'))
 sd=security.SECURITY_DESCRIPTOR()
 sd.SetSecurityDescriptorOwner(security.ConvertStringSidToSid('S-1-5-18'),False)
 sd.SetSecurityDescriptorDacl(True,acl,False)
 monkeypatch.setattr(security,'GetNamedSecurityInfo',lambda *_:sd)
 return provenance,paths,package,root,retained,{'transaction_id':'11111111-1111-4111-8111-111111111111'}


@pytest.mark.parametrize('tree_state',['complete','partial','absent'])
@pytest.mark.parametrize('native_state',[5,-1])
def test_interrupted_reconciliation_reads_verified_legacy_servicing_tree(retained_reconciliation,monkeypatch,tree_state,native_state):
 """A retained tree is repair evidence before and after native old-MSI removal."""
 import shutil
 provenance,paths,package,root,retained,request=retained_reconciliation
 monkeypatch.setattr(legacy,'NativeMsi',lambda:SimpleNamespace(product=lambda _:native_state))
 if tree_state=='partial':(root/'core.exe').unlink()
 elif tree_state=='absent':shutil.rmtree(root)
 before={p:p.read_bytes() for p in paths.install_root.rglob('*') if p.is_file()}
 provenance.validate_interrupted_reconciliation(paths,request)
 assert before=={p:p.read_bytes() for p in paths.install_root.rglob('*') if p.is_file()}


@pytest.mark.parametrize('defect',['root-writer','leaf-writer','ancestor-writer','hardlink','unknown-file',
 'wrong-bytes','wrong-marker','different-marker-bytes','unknown-package','wrong-product','wrong-version',
 'absent-unbound','modern-retained','candidate-servicing-acl','selector-servicing-acl','bundle-servicing-acl','junction'])
def test_retained_servicing_exception_keeps_other_reconciliation_guards(retained_reconciliation,monkeypatch,defect):
 import shutil
 import win32security as security
 provenance,paths,package,root,retained,request=retained_reconciliation
 if defect in {'root-writer','leaf-writer'}:
  trusted=security.GetNamedSecurityInfo
  acl=security.ACL();acl.AddAccessAllowedAce(security.ACL_REVISION,0x1f01ff,security.ConvertStringSidToSid('S-1-5-32-545'))
  sd=security.SECURITY_DESCRIPTOR();sd.SetSecurityDescriptorOwner(security.ConvertStringSidToSid('S-1-5-18'),False)
  sd.SetSecurityDescriptorDacl(True,acl,False)
  bad=root if defect=='root-writer' else root/'core.exe'
  monkeypatch.setattr(security,'GetNamedSecurityInfo',lambda path,*args:sd if str(path)==str(bad) else trusted(path,*args))
 elif defect=='ancestor-writer':monkeypatch.setattr(fence,'assert_namespace_security',lambda *_:(_ for _ in ()).throw(ValueError('parent writer')))
 elif defect=='hardlink':os.link(root/'core.exe',root.parent/'outside-alias.exe')
 elif defect=='unknown-file':(root/'unknown.dll').write_bytes(b'foreign')
 elif defect=='wrong-bytes':(root/'core.exe').write_bytes(b'tampered')
 elif defect=='wrong-marker':(root/provenance.MSI_MARKER).write_text('{}')
 elif defect=='different-marker-bytes':(root/provenance.MSI_MARKER).write_bytes(bytes.fromhex(retained.record['original_marker_bytes'])+b'\n')
 elif defect in {'unknown-package','absent-unbound'}:
  retained.record['package']['sha256']='0'*64
  if defect=='absent-unbound':shutil.rmtree(root)
 elif defect=='wrong-product':retained.record['package']['product_code']='{11111111-1111-4111-8111-111111111111}'
 elif defect=='wrong-version':
  from dataclasses import replace
  retained.identity=replace(retained.identity,version='3.2.81')
 elif defect=='modern-retained':retained.record['compatibility_foundations']=[]
 elif defect=='candidate-servicing-acl':(paths.versions_root/'3.2.106').mkdir()
 elif defect=='selector-servicing-acl':
  raw=json.dumps({'version':package.version}).encode();paths.current_path.write_bytes(raw)
  plan=provenance._read_plan(None,None,None)
  plan.update(current_before=raw.hex(),current_after=raw.hex())
  monkeypatch.setattr(provenance,'_read_plan',lambda *_:plan)
 elif defect=='bundle-servicing-acl':
  (root/provenance.BUNDLE_FILENAME).write_bytes(b'{}')
  retained.record['original_manifest_bytes']=b'{}'.hex()
 elif defect=='junction':
  import subprocess
  target=paths.install_root.parent/'outside';target.mkdir();(target/'library.dll').write_bytes(b'foreign')
  link=root/'linked'
  subprocess.run(['cmd.exe','/c','mklink','/J',str(link),str(target)],check=True,capture_output=True)
  # Remove just the junction, including when an assertion fails; never its target.
  try:
   with pytest.raises(ValueError):provenance.validate_interrupted_reconciliation(paths,request)
  finally:os.rmdir(link)
  return
 with pytest.raises(ValueError):provenance.validate_interrupted_reconciliation(paths,request)


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
