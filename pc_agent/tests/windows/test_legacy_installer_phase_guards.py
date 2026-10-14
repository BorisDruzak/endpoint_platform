"""A rejected native legacy target cannot reach reconciliation or startup."""
import json
from types import SimpleNamespace
import pytest
from pc_agent.tests.windows.test_installation_provenance import handoff_input
from pc_agent.platform.windows import installer_transaction_bridge as bridge,installer_fence as fence
from pc_agent.platform.windows import installer_data_security as data,msi_inventory as msi,legacy_foundation_upgrade as legacy


@pytest.mark.parametrize('phase',['msi-preflight','reconcile','finish'])
def test_rejected_replacement_has_no_phase_completion_or_fence_progress(handoff_input,monkeypatch,phase):
    provenance,paths,root,request,expected=handoff_input
    provenance.prepare_installer_provenance(paths,request)
    native=json.dumps({'schema_version':1,'version':expected.identity.version,
        'source_revision':expected.identity.source_revision},indent=2).encode()+b'\n'
    paths.current_path.write_bytes(native)
    (root/'.endpoint-msi-runtime.json').write_text(json.dumps({'schema_version':1,
        'version':expected.identity.version,'component_guid':'33333333-3333-4333-8333-333333333333'}))
    monkeypatch.setattr(msi,'read_native_selector',lambda *_:native)
    monkeypatch.setattr(bridge,'_request_data',lambda *_:request)
    monkeypatch.setattr(data,'verify_preserved',lambda *_:None)
    monkeypatch.setattr(data,'before_native',lambda *_:None)
    cap={'operation':'install','recovery':False,'package':request['release'],
        'transaction_id':request['transaction_id'],'selected':request['selected'],'previous':request['previous'],
        'service_states':{'EndpointAgent':'stopped','EndpointAgentUpdater':'stopped'}}
    fence.publish_fence(paths,bridge._public_fence(expected,cap))
    before=(fence.state_root(paths)/'transaction.json').read_bytes()
    guarded=[];completed=[]
    def reject(actual,actual_request,*args,**kwargs):
        assert actual is paths and actual_request==request
        guarded.append(phase);raise ValueError('PROVENANCE_CONFLICT')
    monkeypatch.setattr(legacy,'verify_native_preflight',reject)
    monkeypatch.setattr(legacy,'verify_completed_replacement',reject)
    client=SimpleNamespace(capability=cap,phase=phase,checkpoint=lambda:None,
        identity=SimpleNamespace(value={'pid':200,'created':2000,'hash':'a'*64}),request=lambda *args:completed.append(args))
    with pytest.raises(ValueError):bridge._execute_authorized_phase(client,paths,feature_states=(2,3,2,3))
    assert guarded==[phase] and completed==[]
    assert (fence.state_root(paths)/'transaction.json').read_bytes()==before


@pytest.mark.parametrize('legacy_history,current,valid',[(True,'native',True),(True,'absent',True),
    (True,'alternate',False),(False,'native',False),(False,'absent',False)])
def test_recovery_native_selector_requires_exact_prepared_legacy_history(handoff_input,monkeypatch,legacy_history,current,valid):
    provenance,paths,root,request,expected=handoff_input
    provenance.prepare_installer_provenance(paths,request)
    native=json.dumps({'schema_version':1,'version':expected.identity.version,
        'source_revision':expected.identity.source_revision},indent=2).encode()+b'\n'
    monkeypatch.setattr(msi,'read_native_selector',lambda *_:native)
    monkeypatch.setattr(legacy,'prepared_predecessor',lambda *_:SimpleNamespace() if legacy_history else None)
    if current=='absent':paths.current_path.unlink()
    else:paths.current_path.write_bytes(native+(b' ' if current=='alternate' else b''))
    if valid:bridge._validate_install_recovery(paths,request)
    else:
        with pytest.raises(ValueError):bridge._validate_install_recovery(paths,request)
