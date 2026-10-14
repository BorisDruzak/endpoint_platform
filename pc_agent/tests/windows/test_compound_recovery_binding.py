"""A new owner may resume exact original facts, never replace their baseline."""
from copy import deepcopy
from hashlib import sha256
import json

import pytest

from pc_agent.tests.windows.test_compound_upgrade_plan import inputs
from pc_agent.platform.windows import compound_upgrade_plan as plan


@pytest.fixture
def recovery(inputs):
    cap,old,fence=deepcopy(inputs)
    original=plan.make_plan(cap,old,fence,browser_startup={'start_type':2,'delayed_auto':False})
    raw=json.dumps(original,separators=(',',':')).encode('ascii')
    current=deepcopy(cap)
    current.update(session_id='66666666-6666-4666-8666-666666666666',recovery=True)
    current['owner']={**current['owner'],'pid':101,'created':1001}
    current['compound']['upgrade_id']='77777777-7777-4777-8777-777777777777'
    current['compound']['old']['session_id']='88888888-8888-4888-8888-888888888888'
    current['compound']['recovery']={'original_upgrade_id':original['upgrade_id'],
        'original_plan_sha256':sha256(raw).hexdigest(),'predecessor_upgrade_id':original['upgrade_id'],
        'predecessor_plan_sha256':sha256(raw).hexdigest(),'mode':'replace-foundation'}
    return current,original,raw,cap


def test_recovery_copies_exact_original_before_state_with_new_owner_and_sessions(recovery):
    current,original,raw,cap=recovery
    before=deepcopy(original)
    result=plan.make_recovery_plan(current,original,raw,cap)
    assert original==before and result['schema_version']==2
    for key in ('selected','previous','service_startup','browser_startup'):assert result[key]==original[key]
    assert result['owner']==current['owner'] and result['phase']=='prepared'
    assert result['recovery']==current['compound']['recovery']


@pytest.mark.parametrize('defect',['owner-reuse','session-reuse','old-session-reuse','old-package','new-package',
    'helper','transaction','original-hash','selected','previous','mode','fresh-flag','extra'])
def test_recovery_rejects_rebinding_or_rebaselining(recovery,defect):
    current,original,raw,cap=recovery
    if defect=='owner-reuse':current['owner']=cap['owner']
    elif defect=='session-reuse':current['session_id']=cap['session_id']
    elif defect=='old-session-reuse':current['compound']['old']['session_id']=original['old']['session_id']
    elif defect=='old-package':current['compound']['old']['package']['source_revision']='0'*40
    elif defect=='new-package':current['package']['source_revision']='0'*40
    elif defect=='helper':current['helper_sha256']='0'*64
    elif defect=='transaction':current['transaction_id']='99999999-9999-4999-8999-999999999999'
    elif defect=='original-hash':current['compound']['recovery']['original_plan_sha256']='0'*64
    elif defect=='selected':current['selected']='0'*64
    elif defect=='previous':current['previous']='0'*64
    elif defect=='mode':current['compound']['recovery']['mode']='idle-is-settled'
    elif defect=='fresh-flag':current['recovery']=False
    elif defect=='extra':current['compound']['recovery']['reset_original']=True
    with pytest.raises(ValueError):plan.make_recovery_plan(current,original,raw,cap)


def test_successor_repair_has_no_fabricated_old_script_return(recovery):
    current,original,raw,cap=recovery
    current['compound']['recovery']['mode']='repair-successor'
    current['compound']['old']['session_id']=original['old']['session_id']
    record=plan.make_recovery_plan(current,original,raw,cap)
    with pytest.raises(ValueError):plan.next_phase(record,current,'old-script-returned',native_result=0)
    record=plan.next_phase(record,current,'repair-script-returned',native_result=0)
    record=plan.next_phase(record,current,'repair-committed',native_result=0)
    assert record['phase']=='repair-committed'


@pytest.fixture
def stored_recovery(recovery,tmp_path,monkeypatch):
    from pc_agent.platform.windows import installer_fence as fence,installer_transaction_bridge as bridge
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    current,original,raw,cap=recovery
    paths=WindowsUpdatePaths(tmp_path/'Agent',tmp_path/'data/updates/pending_update.json')
    root=fence.state_root(paths);root.mkdir()
    original_root=root/'upgrades'/original['upgrade_id'];original_root.mkdir(parents=True)
    (original_root/'plan.json').write_bytes(raw)
    (root/'upgrade.json').write_text(json.dumps(plan._barrier(original)))
    monkeypatch.setattr(fence,'assert_state_security',lambda *_a,**_k:None)
    monkeypatch.setattr(fence,'protect_state',lambda *_a,**_k:None)
    monkeypatch.setattr(bridge,'_read_capability',lambda _paths,session:cap if session==cap['session_id'] else current)
    record=plan.make_recovery_plan(current,original,raw,cap)
    return paths,current,record,original_root,raw


def test_recovery_selects_new_barrier_without_changing_original_storage(stored_recovery):
    paths,cap,record,original_root,before=stored_recovery
    plan.publish_recovery_plan(paths,cap,record)
    assert plan.read_plan(paths,cap)==record and plan.has_active_upgrade(paths)
    assert (original_root/'plan.json').read_bytes()==before


@pytest.mark.parametrize('defect',['original','predecessor','before-state','owner','publication-loss'])
def test_recovery_rejects_changed_original_or_predecessor_and_retains_exclusion(stored_recovery,defect,monkeypatch):
    from pc_agent.platform.windows import durable_state
    paths,cap,record,original_root,before=stored_recovery
    if defect=='original':(original_root/'plan.json').write_bytes(before+b' ')
    elif defect=='predecessor':cap['compound']['recovery']['predecessor_plan_sha256']='0'*64;record['recovery']=deepcopy(cap['compound']['recovery'])
    elif defect=='before-state':record['service_startup']['EndpointAgent']['start_type']=3
    elif defect=='owner':cap['owner']['pid']=100;cap['owner']['created']=1000;record['owner']=deepcopy(cap['owner'])
    elif defect=='publication-loss':
        write=durable_state.write_json_atomic
        def lost(path,*args,**kwargs):
            result=write(path,*args,**kwargs)
            if path.name=='upgrade.json':raise OSError('active pointer result lost')
            return result
        monkeypatch.setattr(durable_state,'write_json_atomic',lost)
    with pytest.raises((ValueError,OSError)):plan.publish_recovery_plan(paths,cap,record)
    assert plan.has_active_upgrade(paths)
    if defect!='original':assert (original_root/'plan.json').read_bytes()==before
    if defect=='publication-loss':assert plan.read_plan(paths,cap)==record


def test_recovery_child_is_a_new_scope_without_overwriting_original_child(tmp_path):
    from pc_agent.platform.windows import installer_fence as fence
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    paths=WindowsUpdatePaths(tmp_path/'Agent',tmp_path/'data/updates/pending_update.json')
    transaction='33333333-3333-4333-8333-333333333333'
    attempt='77777777-7777-4777-8777-777777777777'
    root=fence.state_root(paths)/'children'/transaction;root.mkdir(parents=True)
    original=root/'transaction.json';original.write_bytes(b'immutable original child evidence')
    with fence.child_fence(transaction,attempt_id=attempt):
        assert fence.fence_path(paths)==root/attempt/'transaction.json'
    assert original.read_bytes()==b'immutable original child evidence'


@pytest.mark.parametrize('entry',['read_plan','read_recovery_original','inspect_recovery_authority'])
@pytest.mark.parametrize('defect',['changed','missing'])
def test_each_attempt_read_retains_exact_distinct_predecessor_binding(stored_recovery,monkeypatch,entry,defect):
    from pc_agent.platform.windows import installer_transaction_bridge as bridge
    paths,first,record,original_root,original_bytes=stored_recovery
    original_cap=bridge._read_capability(paths,json.loads(original_bytes)['new']['session_id'])
    original_cap['service_states']={'EndpointAgent':'stopped','EndpointAgentUpdater':'stopped'}
    plan.publish_recovery_plan(paths,first,record)
    predecessor=plan._root(paths,first)/'plan.json';raw=predecessor.read_bytes()
    current=deepcopy(first)
    current['owner']={**current['owner'],'pid':102,'created':1002}
    current['session_id']='99999999-9999-4999-8999-999999999999'
    current['compound']['upgrade_id']='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
    current['compound']['old']['session_id']='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
    current['compound']['recovery'].update(predecessor_upgrade_id=first['compound']['upgrade_id'],
        predecessor_plan_sha256=sha256(raw).hexdigest())
    caps={c['session_id']:c for c in (original_cap,first,current)}
    monkeypatch.setattr(bridge,'_read_capability',lambda _paths,session:caps[session])
    original=json.loads(original_bytes)
    second=plan.make_recovery_plan(current,original,original_bytes,original_cap)
    plan.publish_recovery_plan(paths,current,second)
    assert plan.read_plan(paths,current)==second
    if defect=='changed':predecessor.write_bytes(raw+b' ')
    else:predecessor.unlink()
    with pytest.raises((ValueError,FileNotFoundError)):
        if entry=='inspect_recovery_authority':plan.inspect_recovery_authority(paths,current['package'])
        else:getattr(plan,entry)(paths,current)
    assert (original_root/'plan.json').read_bytes()==original_bytes
    assert plan.has_active_upgrade(paths)


@pytest.mark.parametrize('defect',['torn','digest','valid','foreign-barrier','hardlink','security'])
def test_readonly_locator_handles_invalid_content_but_rejects_unsafe_terminal_namespace(stored_recovery,monkeypatch,defect):
    import os
    from types import SimpleNamespace
    from pc_agent.platform.windows import installer_fence as fence,installer_transaction_bridge as bridge,msi_inventory
    paths,attempt,record,original_root,raw=stored_recovery
    original=json.loads(raw);barrier=plan._barrier(original)
    original_cap=bridge._read_capability(paths,original['new']['session_id'])
    original_cap['service_states']={'EndpointAgent':'stopped','EndpointAgentUpdater':'stopped'}
    history=fence.state_root(paths)/'upgrade-history'/original['upgrade_id'];history.mkdir(parents=True)
    (history/'barrier.json').write_text(json.dumps(barrier))
    ready={**barrier,'successor_product_code':original['new']['package']['product_code'],
        'source_revision':original['new']['package']['source_revision'],'phase':'ready'}
    ready_raw=json.dumps(ready).encode();(history/'ready.json').write_bytes(ready_raw)
    marker={**{k:v for k,v in ready.items() if k!='phase'},'ready_sha256':sha256(ready_raw).hexdigest()}
    terminal=history/'complete.json';terminal.write_text(json.dumps(marker))
    if defect=='torn':terminal.write_bytes(b'{')
    elif defect=='digest':marker['ready_sha256']='0'*64;terminal.write_text(json.dumps(marker))
    elif defect=='foreign-barrier':(history/'barrier.json').write_text(json.dumps({**barrier,'new_package_sha256':'0'*64}))
    elif defect=='hardlink':os.link(terminal,history/'alias.json')
    elif defect=='security':
        def security(path,**_kw):
            if path==terminal:raise ValueError('PROVENANCE_CONFLICT')
        monkeypatch.setattr(fence,'assert_state_security',security)
    before={str(p):p.read_bytes() for p in fence.state_root(paths).rglob('*') if p.is_file()}
    locator={**deepcopy(original_cap),'recovery':True,'recovery_parent':original['upgrade_id']}
    locator.pop('compound')
    monkeypatch.setattr(bridge,'_settled',lambda *_:None)
    monkeypatch.setattr(msi_inventory,'NativeMsi',lambda:SimpleNamespace(product=lambda product:
        5 if product==locator['package']['product_code'] else -1))
    done=[];client=SimpleNamespace(capability=locator,phase='inspect-compound',request=lambda *a:done.append(a))
    if defect in {'torn','digest'}:
        result=bridge.execute_authorized_phase(client,paths)
        assert result['mode']=='repair-successor' and result['parent_upgrade_id']==original['upgrade_id']
        assert done==[('complete',result)]
    else:
        with pytest.raises(ValueError):bridge.execute_authorized_phase(client,paths)
        assert done==[]
    assert before=={str(p):p.read_bytes() for p in fence.state_root(paths).rglob('*') if p.is_file()}
