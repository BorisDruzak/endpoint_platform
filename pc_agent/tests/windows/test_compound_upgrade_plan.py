"""A successor cannot adopt another package, session, owner or before-state."""
from copy import deepcopy
import json
import os
from uuid import uuid4

import pytest

from pc_agent.platform.windows import compound_upgrade_plan as plan
from pc_agent.tests.windows.test_installer_fence import native_protected_root


@pytest.fixture
def inputs():
    old_release={'schema_version':'endpoint_windows_release_v1','version':'3.2.92',
        'source_revision':'a'*40,'package_sha256':'b'*64,
        'product_code':'{11111111-1111-4111-8111-111111111111}','initial_runtime_tree_sha256':'c'*64}
    new_release={**old_release,'version':'3.2.94','package_sha256':'d'*64,
        'source_revision':'e'*40,'product_code':'{22222222-2222-4222-8222-222222222222}'}
    owner={'pid':100,'created':1000,'hash':'a'*64,'sid':'S-1-5-18','elevated':True}
    old_cap={'transaction_id':'11111111-1111-4111-8111-111111111111',
        'session_id':'22222222-2222-4222-8222-222222222222','package':old_release,
        'helper_sha256':'f'*64,'owner':owner,'operation':'uninstall','recovery':False,'uninstall_finalization':False}
    cap={'transaction_id':'33333333-3333-4333-8333-333333333333',
        'session_id':'44444444-4444-4444-8444-444444444444','package':new_release,
        'helper_sha256':'1'*64,'owner':owner,'operation':'install',
        'selected':'2'*64,'previous':None,'recovery':False,'uninstall_finalization':False,
        'compound':{'upgrade_id':'55555555-5555-4555-8555-555555555555',
            'old':{key:old_cap[key] for key in ('transaction_id','session_id','package','helper_sha256')}}}
    fence={'transaction_id':old_cap['transaction_id'],'package':{'sha256':'b'*64,
        'version':'3.2.92','source_revision':'a'*40,'product_code':old_release['product_code']},
        'operation':'uninstall','selected':'2'*64,'previous':None,'startup_restored':False,
        'service_startup':{'EndpointAgent':{'start_type':2,'delayed_auto':False},
            'EndpointAgentUpdater':{'start_type':3,'delayed_auto':False}}}
    return cap,old_cap,fence


@pytest.mark.parametrize('defect',['owner','old-session','old-package','old-helper','selected','previous','operation','startup-restored','old-recovery','old-finalization'])
def test_prepare_requires_original_old_capability_and_fence(inputs,defect):
    cap,old,fence=deepcopy(inputs)
    if defect=='owner': old['owner']['created']+=1;cap['owner']={**cap['owner'],'created':1000}
    elif defect=='old-session': old['session_id']='66666666-6666-4666-8666-666666666666'
    elif defect=='old-package': old['package']['package_sha256']='3'*64;cap['compound']['old']['package']={**cap['compound']['old']['package'],'package_sha256':'b'*64}
    elif defect=='old-helper': old['helper_sha256']='3'*64
    elif defect=='selected': fence['selected']='3'*64
    elif defect=='previous': fence['previous']='3'*64
    elif defect=='operation': old['operation']='install'
    elif defect=='startup-restored': fence['startup_restored']=True
    elif defect=='old-recovery': old['recovery']=True
    else: old['uninstall_finalization']=True
    with pytest.raises(ValueError): plan.make_plan(cap,old,fence)


def test_plan_keeps_exact_original_bindings_and_has_no_secret(inputs):
    cap,old,fence=inputs
    value=plan.make_plan(cap,old,fence)
    assert value['old']==cap['compound']['old']
    assert value['new']=={key:cap[key] for key in ('transaction_id','session_id','package','helper_sha256')}
    assert value['service_startup']==fence['service_startup']
    assert 'secret' not in str(value)


def test_browser_startup_is_captured_separately_without_changing_old_fence(inputs):
    cap,old,fence=inputs;before=deepcopy(fence)
    startup={'start_type':2,'delayed_auto':False}
    value=plan.make_plan(cap,old,fence,browser_startup=startup)
    assert value['browser_startup']==startup and fence==before
    startup['start_type']=4
    assert value['browser_startup']['start_type']==2
    value['browser_startup']={'start_type':'2','delayed_auto':False}
    with pytest.raises(ValueError):plan.validate_bound_plan(value,cap)


@pytest.mark.parametrize('defect',['owner','session','package','helper','selector','unknown-field'])
def test_current_capability_cannot_rebind_plan(inputs,defect):
    cap,old,fence=inputs
    value=plan.make_plan(cap,old,fence);other=deepcopy(cap)
    if defect=='owner': other['owner']['created']+=1
    elif defect=='session': other['session_id']='66666666-6666-4666-8666-666666666666'
    elif defect=='package': other['package']['package_sha256']='3'*64
    elif defect=='helper': other['helper_sha256']='3'*64
    elif defect=='selector': other['selected']='3'*64
    else: value['invented']=True
    with pytest.raises(ValueError): plan.validate_bound_plan(value,other)


def test_ordered_native_results_do_not_authorize_early_retirement(inputs):
    cap,old,fence=inputs;value=plan.make_plan(cap,old,fence)
    with pytest.raises(ValueError): plan.next_phase(value,cap,'committed')
    value=plan.next_phase(value,cap,'old-script-returned',native_result=0)
    with pytest.raises(ValueError): plan.next_phase(value,cap,'old-script-returned',native_result=0)
    value=plan.next_phase(value,cap,'new-script-returned',native_result=0)
    with pytest.raises(ValueError): plan.next_phase(value,cap,'retired')
    value=plan.next_phase(value,cap,'committed',native_result=0)
    for phase in ('retired','reconciled','ready'):
        value=plan.next_phase(value,cap,phase)
    assert value['phase']=='ready' and value['sequence']==6


@pytest.mark.parametrize('code',[None,1603,1618,3010,1641,True,'0'])
def test_nonzero_reboot_or_untyped_result_never_claims_native_success(inputs,code):
    cap,old,fence=inputs;value=plan.make_plan(cap,old,fence)
    with pytest.raises(ValueError): plan.next_phase(value,cap,'old-script-returned',native_result=code)


def test_child_fence_preserves_the_immutable_old_global_fence(tmp_path, monkeypatch):
    from pc_agent.platform.windows import installer_fence as fence
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    from pc_agent.tests.windows.test_installer_fence import state
    paths=WindowsUpdatePaths(tmp_path/'Agent',tmp_path/'data/updates/pending_update.json')
    root=fence.state_root(paths);root.mkdir()
    old=state();global_path=root/'transaction.json'
    global_path.write_text(json.dumps(old),encoding='utf-8');before=global_path.read_bytes()
    child_id='33333333-3333-4333-8333-333333333333'
    child_root=root/'children'/child_id;child_root.mkdir(parents=True)
    child={**old,'transaction_id':child_id,'package':{**old['package'],'sha256':'d'*64,'version':'3.2.94'}}
    (child_root/'transaction.json').write_text(json.dumps(child),encoding='utf-8')
    monkeypatch.setattr(fence,'assert_state_security',lambda *_args,**_kwargs:None)
    monkeypatch.setattr(fence,'protect_state',lambda *_args,**_kwargs:None)
    with fence.child_fence(child_id):
        assert fence.read_fence(paths)==child
        fence.publish_fence(paths,{**child,'sequence':2})
        assert fence.fence_path(paths)==child_root/'transaction.json'
    assert fence.read_fence(paths)==old and global_path.read_bytes()==before


def test_parent_barrier_blocks_launch_even_without_an_old_global_fence(tmp_path, monkeypatch):
    from pc_agent.platform.windows import installer_fence as fence
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths=WindowsUpdatePaths(tmp_path/'Agent',tmp_path/'data/updates/pending_update.json')
    root=fence.state_root(paths);root.mkdir()
    barrier={'schema_version':1,'upgrade_id':'55555555-5555-4555-8555-555555555555',
        'new_transaction_id':'33333333-3333-4333-8333-333333333333',
        'old_package_sha256':'b'*64,'new_package_sha256':'d'*64}
    (root/'upgrade.json').write_text(json.dumps(barrier),encoding='utf-8')
    monkeypatch.setattr(fence,'assert_state_security',lambda *_args,**_kwargs:None)
    with pytest.raises(ValueError,match='INSTALLER_RECOVERY_REQUIRED'):
        fence.assert_launch_allowed(paths)


@pytest.mark.skipif(os.name != 'nt', reason='native protected transaction storage')
def test_private_plan_publication_retry_preserves_initial_record(inputs,native_protected_root,monkeypatch):
    from pc_agent.platform.windows import installer_fence as fence,durable_state
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    from pc_agent.platform.windows.installation_provenance import _archive_directory
    paths=WindowsUpdatePaths(native_protected_root/'Agent',native_protected_root/'data/updates/pending_update.json')
    fence.protect_state(native_protected_root)
    _archive_directory(native_protected_root,'installer-state')
    cap,old,original=inputs;record=plan.make_plan(cap,old,original)
    write=durable_state.write_json_atomic
    def interrupted(path,*args,**kwargs):
        if path.name=='upgrade.json': raise OSError('fixed publication interruption')
        return write(path,*args,**kwargs)
    monkeypatch.setattr(durable_state,'write_json_atomic',interrupted)
    with pytest.raises(OSError,match='publication interruption'): plan.publish_plan(paths,cap,record)
    stored=plan._root(paths,cap)/'plan.json';before=stored.read_bytes()
    fence.assert_state_security(stored,secret=True)
    monkeypatch.setattr(durable_state,'write_json_atomic',write)
    plan.publish_plan(paths,cap,record)
    assert stored.read_bytes()==before and plan.read_plan(paths,cap)==record
    changed={**record,'selected':'3'*64}
    with pytest.raises(ValueError): plan.publish_plan(paths,cap,changed)
    assert stored.read_bytes()==before


@pytest.mark.skipif(os.name != 'nt', reason='Windows scoped update mutex')
def test_parent_upgrade_barrier_also_blocks_ordinary_updater(tmp_path,monkeypatch):
    from pc_agent.platform.windows import installer_fence as fence,update_transaction as transaction
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths=WindowsUpdatePaths(tmp_path/'Agent',tmp_path/'data/updates/pending_update.json')
    paths.updates_root.parent.mkdir()
    root=fence.state_root(paths);root.mkdir()
    barrier={'schema_version':1,'upgrade_id':'55555555-5555-4555-8555-555555555555',
        'new_transaction_id':'33333333-3333-4333-8333-333333333333',
        'old_package_sha256':'b'*64,'new_package_sha256':'d'*64}
    (root/'upgrade.json').write_text(json.dumps(barrier),encoding='utf-8')
    monkeypatch.setattr(fence,'assert_state_security',lambda *_args,**_kwargs:None)
    monkeypatch.setattr(transaction,'_MUTEX_NAME','Local\\EndpointCompoundTest-'+uuid4().hex)
    with pytest.raises(transaction.UpdateInProgress,match='INSTALLER_RECOVERY_REQUIRED'):
        with transaction.update_transaction(paths): pytest.fail('updater admitted through active parent plan')
