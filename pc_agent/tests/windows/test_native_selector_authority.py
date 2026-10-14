"""Only the exact successor package's authored selector is an intermediate."""
import json
from types import SimpleNamespace

import pytest

from pc_agent.platform.windows import msi_inventory
from pc_agent.tests.windows.test_installation_provenance import handoff_input


@pytest.mark.parametrize('defect', ['none', 'version', 'source', 'fields', 'duplicate', 'size', 'file'])
def test_native_selector_resource_is_bound_to_runtime_and_installed_file(monkeypatch, defect):
    value={'schema_version':1,'version':'3.2.94','source_revision':'e'*40}
    good=json.dumps(value,separators=(',',':')).encode()
    if defect=='version': value['version']='3.2.93'
    elif defect=='source': value['source_revision']='f'*40
    elif defect=='fields': value['approved']=True
    raw=json.dumps(value,separators=(',',':')).encode()
    if defect=='duplicate': raw=b'{"schema_version":1,"schema_version":1,"version":"3.2.94","source_revision":"'+b'e'*40+b'"}'
    file=msi_inventory.InstalledFile('wrong' if defect=='file' else 'filCurrentSelector',
        'cmpCurrentSelector','current.json',len(good)+(1 if defect=='size' else 0))
    expected=SimpleNamespace(identity=SimpleNamespace(version='3.2.94',source_revision='e'*40),
        package=SimpleNamespace(files=(file,)))
    calls=[]
    def binary(path,name,*,maximum):
        calls.append((name,maximum));return raw
    monkeypatch.setattr(msi_inventory,'read_binary',binary)
    if defect=='none':
        assert msi_inventory.read_native_selector('pinned-package',expected)==good
    else:
        with pytest.raises(ValueError): msi_inventory.read_native_selector('pinned-package',expected)
    assert calls==[('EndpointNativeCurrentSelector',4096)]


def test_reconciliation_accepts_only_explicit_exact_native_selector(handoff_input, monkeypatch):
    module,paths,root,request,expected=handoff_input
    module.prepare_installer_provenance(paths,request)
    native=json.dumps({'schema_version':1,'version':expected.identity.version,
        'source_revision':expected.identity.source_revision},indent=2).encode()+b'\n'
    monkeypatch.setattr(msi_inventory,'read_native_selector',lambda *_: native)
    paths.current_path.write_bytes(native)
    with pytest.raises(ValueError): module.validate_interrupted_reconciliation(paths,request)
    module.validate_interrupted_reconciliation(paths,request,native_current=native)
    paths.current_path.write_bytes(native+b' ')
    with pytest.raises(ValueError): module.validate_interrupted_reconciliation(paths,request,native_current=native)


@pytest.mark.parametrize('defect',['none','alternate-bytes'])
def test_nested_repair_preflight_uses_actual_native_selector_predicate(handoff_input, monkeypatch, defect):
    from pc_agent.platform.windows import installer_transaction_bridge as bridge, compound_upgrade_plan as plan
    from pc_agent.platform.windows import installer_fence as fence, installer_data_security as data
    from pc_agent.tests.windows.test_compound_upgrade_plan import inputs
    module,paths,root,request,expected=handoff_input
    module.prepare_installer_provenance(paths,request)
    native=json.dumps({'schema_version':1,'version':expected.identity.version,
        'source_revision':expected.identity.source_revision},indent=2).encode()+b'\n'
    paths.current_path.write_bytes(native if defect=='none' else native+b' ')
    monkeypatch.setattr(msi_inventory,'read_native_selector',lambda *_:native)
    cap,_,_=inputs.__wrapped__()
    cap.update(package=request['release'],transaction_id=request['transaction_id'],
        selected=request['selected'],previous=request['previous'],recovery=True,
        service_states={'EndpointAgent':'stopped','EndpointAgentUpdater':'stopped'})
    cap['compound']['old']['package']['product_code']='{33333333-3333-4333-8333-333333333333}'
    monkeypatch.setattr(bridge,'_request_data',lambda *_:request)
    monkeypatch.setattr(plan,'read_plan',lambda *_:{'phase':'prepared','recovery':{'mode':'repair-successor'}})
    monkeypatch.setattr(msi_inventory,'NativeMsi',lambda:SimpleNamespace(product=lambda code:
        5 if code==cap['package']['product_code'] else -1))
    fence.publish_fence(paths,bridge._public_fence(expected,cap))
    monkeypatch.setattr(data,'before_native',lambda *_:None)
    class Services:
        def __init__(self,*_):pass
        def __enter__(self):return self
        def __exit__(self,*_):pass
        def assert_quarantined(self):pass
    monkeypatch.setattr(bridge,'InstallerServices',Services)
    done=[]
    client=SimpleNamespace(capability=cap,phase='msi-preflight',request=lambda *args:done.append(args))
    if defect=='none':
        bridge._execute_authorized_phase(client,paths,feature_states=(2,3,2,3))
        assert done==[('complete',{})]
    else:
        with pytest.raises(ValueError):bridge._execute_authorized_phase(client,paths,feature_states=(2,3,2,3))
        assert done==[]


@pytest.mark.parametrize('defect',['none','alternate-bytes'])
def test_ordinary_install_reconcile_accepts_only_exact_package_native_selector(handoff_input,monkeypatch,defect):
    from pc_agent.platform.windows import installer_transaction_bridge as bridge,installer_fence as fence,installer_data_security as data
    module,paths,root,request,expected=handoff_input
    module.prepare_installer_provenance(paths,request)
    native=json.dumps({'schema_version':1,'version':expected.identity.version,
        'source_revision':expected.identity.source_revision},indent=2).encode()+b'\n'
    paths.current_path.write_bytes(native if defect=='none' else native+b' ')
    (root/'.endpoint-msi-runtime.json').write_text(json.dumps({'schema_version':1,
        'version':expected.identity.version,'component_guid':'33333333-3333-4333-8333-333333333333'}))
    monkeypatch.setattr(msi_inventory,'read_native_selector',lambda *_:native)
    monkeypatch.setattr(bridge,'_request_data',lambda *_:request)
    monkeypatch.setattr(data,'verify_preserved',lambda *_:None)
    cap={'operation':'install','recovery':False,'package':request['release'],
        'transaction_id':request['transaction_id'],'selected':request['selected'],'previous':request['previous'],
        'service_states':{'EndpointAgent':'stopped','EndpointAgentUpdater':'stopped'}}
    fence.publish_fence(paths,bridge._public_fence(expected,cap))
    done=[]
    client=SimpleNamespace(capability=cap,phase='reconcile',checkpoint=lambda:None,
        identity=SimpleNamespace(value={'pid':200,'created':2000,'hash':'a'*64}),request=lambda *args:done.append(args))
    if defect=='none':
        bridge._execute_authorized_phase(client,paths)
        assert done==[('complete',{'result':'handoff'})]
        assert module.inspect_installed_core(paths,resulting_foundation=expected.identity.version).current.origin=='msi'
    else:
        with pytest.raises(ValueError):bridge._execute_authorized_phase(client,paths)
        assert done==[]


def test_old_native_removal_absence_requires_explicit_transition_authority(handoff_input, monkeypatch):
    module,paths,root,request,expected=handoff_input
    module.prepare_installer_provenance(paths,request)
    paths.current_path.unlink()
    with pytest.raises(ValueError): module.validate_interrupted_reconciliation(paths,request)
    native=json.dumps({'schema_version':1,'version':expected.identity.version,
        'source_revision':expected.identity.source_revision}).encode()
    monkeypatch.setattr(msi_inventory,'read_native_selector',lambda *_: native)
    module.validate_interrupted_reconciliation(paths,request,native_current=native,allow_native_absence=True)
    assert not paths.current_path.exists()


@pytest.mark.parametrize('entry',['validate_interrupted_reconciliation','reconcile_installed_core'])
def test_same_identity_alternate_bytes_cannot_authorize_native_transition(handoff_input, monkeypatch, entry):
    module,paths,root,request,expected=handoff_input
    module.prepare_installer_provenance(paths,request)
    value={'schema_version':1,'version':expected.identity.version,
        'source_revision':expected.identity.source_revision}
    authored=json.dumps(value,separators=(',',':')).encode()
    forged=json.dumps(value,indent=4).encode()+b'\n'
    paths.current_path.write_bytes(forged)
    (root/'.endpoint-msi-runtime.json').write_text(json.dumps({'schema_version':1,
        'version':expected.identity.version,'component_guid':'33333333-3333-4333-8333-333333333333'}))
    monkeypatch.setattr(msi_inventory,'read_native_selector',lambda *_: authored)
    before={str(p):p.read_bytes() for p in paths.install_root.rglob('*') if p.is_file()}
    with pytest.raises(ValueError): getattr(module,entry)(paths,request,native_current=forged)
    assert before=={str(p):p.read_bytes() for p in paths.install_root.rglob('*') if p.is_file()}
