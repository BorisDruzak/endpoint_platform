"""Fresh preparation cannot relabel an arbitrary interrupted old removal."""
from copy import deepcopy
from hashlib import sha256
import json

import pytest

from pc_agent.platform.windows import compound_upgrade_plan as plan
from pc_agent.tests.windows.test_compound_upgrade_plan import inputs


def prepared(inputs):
    cap,seed,fence=deepcopy(inputs)
    seed.update(selected=cap['selected'],previous=cap['previous'])
    old=deepcopy(seed)
    old.update(session_id='66666666-6666-4666-8666-666666666666',recovery=True)
    cap['compound']['old']={key:old[key] for key in plan._BINDING}
    role={'source':{key:seed[key] for key in plan._BINDING},
        'capability_sha256':'7'*64,'fence_sha256':'8'*64,'maintenance_sha256':'9'*64}
    cap['compound']['prepared_old']=role
    return cap,seed,old,fence


def test_prepared_removal_plan_requires_real_distinct_fresh_source(inputs):
    cap,seed,old,fence=prepared(inputs)
    result=plan.make_plan(cap,old,fence,prepared_source=seed)
    assert result['prepared_old']==cap['compound']['prepared_old']
    assert result['old']['session_id']!=result['prepared_old']['source']['session_id']
    assert result['phase']=='prepared' and not cap['recovery']


@pytest.mark.parametrize('defect',['missing-source','source-recovery','source-owner','source-selected',
    'source-package','same-session','wrong-role','fresh-current','extra-role'])
def test_prepared_removal_cannot_adopt_unrelated_or_interrupted_source(inputs,defect):
    cap,seed,old,fence=prepared(inputs)
    if defect=='missing-source':seed=None
    elif defect=='source-recovery':seed['recovery']=True
    elif defect=='source-owner':seed['owner']={**seed['owner'],'created':1001}
    elif defect=='source-selected':seed['selected']='0'*64
    elif defect=='source-package':seed['package']={**seed['package'],'package_sha256':'0'*64}
    elif defect=='same-session':cap['compound']['prepared_old']['source']['session_id']=old['session_id'];seed['session_id']=old['session_id']
    elif defect=='wrong-role':cap['compound']['prepared_old']['source']['helper_sha256']='0'*64
    elif defect=='fresh-current':old['recovery']=False
    else:cap['compound']['prepared_old']['trust_prepared']=True
    with pytest.raises(ValueError):plan.make_plan(cap,old,fence,prepared_source=seed)


@pytest.mark.parametrize('mode',['replace-foundation','repair-successor'])
def test_recovery_preserves_exact_prepared_role_and_before_state(inputs,mode):
    cap,seed,old,fence=prepared(inputs)
    original=plan.make_plan(cap,old,fence,prepared_source=seed)
    raw=json.dumps(original,separators=(',',':')).encode('ascii')
    current=deepcopy(cap)
    current.update(session_id='77777777-7777-4777-8777-777777777777',recovery=True)
    current['owner']={**current['owner'],'pid':101,'created':1001}
    current['compound']['upgrade_id']='88888888-8888-4888-8888-888888888888'
    if mode=='replace-foundation':current['compound']['old']['session_id']='99999999-9999-4999-8999-999999999999'
    current['compound']['recovery']={'original_upgrade_id':original['upgrade_id'],
        'original_plan_sha256':sha256(raw).hexdigest(),'predecessor_upgrade_id':original['upgrade_id'],
        'predecessor_plan_sha256':sha256(raw).hexdigest(),'mode':mode}
    result=plan.make_recovery_plan(current,original,raw,cap)
    assert result['prepared_old']==original['prepared_old']
    current['compound']['prepared_old']['fence_sha256']='0'*64
    with pytest.raises(ValueError):plan.make_recovery_plan(current,original,raw,cap)


@pytest.fixture
def stored_preparation(inputs,tmp_path,monkeypatch):
    from pc_agent.platform.windows import installer_fence as fence_module,installer_transaction_bridge as bridge
    from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
    cap,seed,old,before=prepared(inputs)
    before['phase']='msi-starting'
    paths=WindowsUpdatePaths(tmp_path/'Agent',tmp_path/'data/updates/pending_update.json')
    root=fence_module.state_root(paths)
    archive=root/'prepared-old'/seed['session_id'];archive.mkdir(parents=True)
    (root/'capabilities').mkdir()
    source=root/'capabilities'/f"{seed['session_id']}.json"
    source.write_text(json.dumps(seed))
    role=cap['compound']['prepared_old']
    role['capability_sha256']=sha256(source.read_bytes()).hexdigest()
    maintenance={'transaction_id':seed['transaction_id'],'operation':'uninstall','release':seed['package']}
    for name,value in (('fence',before),('maintenance',maintenance)):
        path=archive/f'{name}.json';path.write_text(json.dumps(value))
        role[name+'_sha256']=sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(fence_module,'assert_state_security',lambda *_a,**_k:None)
    monkeypatch.setattr(bridge,'_read_capability',lambda _p,_s:deepcopy(seed))
    return paths,cap,seed,before,archive,source


def test_read_prepared_source_keeps_original_protected_binding(stored_preparation):
    paths,cap,seed,before,_archive,_source=stored_preparation
    saved,saved_fence,_maintenance=plan.read_prepared_source(paths,cap)
    assert saved==seed and saved_fence==before


@pytest.mark.parametrize('leaf',['capability','fence','maintenance'])
def test_read_prepared_source_refuses_changed_archived_bytes(stored_preparation,leaf):
    paths,cap,_seed,_before,archive,source=stored_preparation
    path=source if leaf=='capability' else archive/f'{leaf}.json'
    path.write_bytes(path.read_bytes()+b' ')
    with pytest.raises(ValueError):plan.read_prepared_source(paths,cap)


def test_preparation_without_parent_grants_no_native_or_recovery_parent(stored_preparation):
    paths,cap,_seed,_before,_archive,_source=stored_preparation
    # A kill after preparation/swap preserves evidence but creates no parent.
    # Recovery must use the exact old package/fence through the existing
    # RecoverInterruptedInstall route; observed absence cannot create a plan.
    assert plan.inspect_recovery_authority(paths,cap['package']) is None
    with pytest.raises((ValueError,FileNotFoundError)):plan.read_plan(paths,cap)


@pytest.mark.parametrize('defect',[None,'fresh-old','wrong-owner','missing-role'])
def test_historical_repair_accepts_only_original_bound_prepared_session(inputs,monkeypatch,defect):
    from pc_agent.platform.windows import compound_installer as installer,installer_transaction_bridge as bridge
    cap,seed,old,before=prepared(inputs)
    original=plan.make_plan(cap,old,before,prepared_source=seed)
    current=deepcopy(cap);current['recovery']=True
    current['owner']={**current['owner'],'pid':101,'created':1001}
    current['compound']['recovery']={'mode':'repair-successor'}
    monkeypatch.setattr(plan,'read_recovery_original',lambda *_a:(original,b'original',cap))
    monkeypatch.setattr(plan,'read_prepared_source',lambda *_a:(seed,before,{}))
    monkeypatch.setattr(bridge,'_read_capability',lambda *_a:old)
    if defect=='fresh-old':old['recovery']=False
    elif defect=='wrong-owner':old['owner']=current['owner']
    elif defect=='missing-role':del current['compound']['prepared_old']
    if defect is None:assert installer._old_capability(None,current)==old
    else:
        with pytest.raises(ValueError):installer._old_capability(None,current)
