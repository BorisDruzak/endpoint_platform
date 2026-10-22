"""Exercise durable child transitions with a modeled native inventory/SCM.

The actual owner policy, package reader and native storage have separate tests;
this fixture never opens real services or installs products.
"""
from copy import deepcopy
from contextlib import contextmanager
import json
from types import SimpleNamespace

import pytest

from pc_agent.tests.windows.test_compound_upgrade_plan import inputs
from pc_agent.platform.windows import installer_transaction_bridge as bridge
from pc_agent.platform.windows import installer_fence as fence, compound_upgrade_plan as plan
from pc_agent.platform.windows import installation_provenance as provenance, msi_inventory, installer_data_security
from pc_agent.platform.windows.update_paths import WindowsUpdatePaths


@pytest.fixture
def staged(inputs,tmp_path,monkeypatch):
    cap,old,original=deepcopy(inputs)
    paths=WindowsUpdatePaths(tmp_path/'Agent',tmp_path/'data/updates/pending_update.json')
    paths.install_root.mkdir();root=fence.state_root(paths);root.mkdir()
    for value in (cap,old):
        value.update(schema_version=1,secret='7'*64,
            pipe_name='EndpointInstaller-'+value['session_id']+'-'+'8'*32,
            service_states={'EndpointAgent':'stopped','EndpointAgentUpdater':'stopped'},
            selected=cap['selected'],previous=cap['previous'])
    expected={}
    for value in (cap,old):
        release=value['package']
        expected[release['package_sha256']]=SimpleNamespace(package=SimpleNamespace(
            sha256=release['package_sha256'],version=release['version'],product_code=release['product_code'],
            package_code='{AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA}'),
            identity=SimpleNamespace(version=release['version'],source_revision=release['source_revision']))
    original.update(schema_version=1,phase='msi-starting',sequence=1,helpers=[],service_states=old['service_states'])
    original['package']['package_code']=expected[old['package']['package_sha256']].package.package_code
    fence.validate_fence(original)
    global_path=root/'transaction.json';global_path.write_text(json.dumps(original))
    caps=root/'capabilities';caps.mkdir();(caps/(old['session_id']+'.json')).write_text(json.dumps(old))
    monkeypatch.setattr(fence,'assert_state_security',lambda *_a,**_k:None)
    monkeypatch.setattr(bridge,'assert_state_security',lambda *_a,**_k:None)
    monkeypatch.setattr(fence,'protect_state',lambda *_a,**_k:None)
    monkeypatch.setattr(msi_inventory,'read_expected_package',lambda _path,release:expected[release['package_sha256']])
    native={old['package']['product_code']:5,cap['package']['product_code']:-1}
    monkeypatch.setattr(msi_inventory,'NativeMsi',lambda:SimpleNamespace(product=lambda product:native[product]))
    events=[]
    # All native configuration boundaries must be isolated on every platform;
    # a modeled SCM must never fall through to the operator's real services.
    from pc_agent.platform.windows import service_control,acl,service_launcher
    for module,names in ((service_control,('configure_service_sids','restrict_updater_start_permissions')),
        (acl,('apply_tray_status_acl',)),(service_launcher,('stop_tray_companions',))):
        for name in names:
            monkeypatch.setattr(module,name,lambda *_a,name=name,**_k:events.append(name))
    monkeypatch.setattr(bridge,'_settled',lambda *_:None)
    monkeypatch.setattr(bridge,'_matching_inspection',lambda *_a,**_k:events.append('inspection'))
    monkeypatch.setattr(provenance,'inspect_installed_core',lambda *_a,**_k:SimpleNamespace(
        current=SimpleNamespace(digest=cap['selected']),previous=None))
    monkeypatch.setattr(msi_inventory,'read_native_selector',lambda *_:b'exact authored selector fixture')
    for name in ('prepare_installer_provenance','validate_interrupted_reconciliation','validate_maintenance_recovery'):
        monkeypatch.setattr(provenance,name,lambda *_a,name=name,**_k:events.append(name))
    monkeypatch.setattr(msi_inventory,'verify_installed',lambda *_:events.append('native-new-verified'))
    monkeypatch.setattr(msi_inventory,'verify_foundation',lambda *_a,**_k:events.append('native-old-foundation-verified'))
    monkeypatch.setattr(msi_inventory,'verify_replaced_product',lambda *_a,**_k:events.append('old-owner-absent'),raising=False)
    monkeypatch.setattr(provenance,'retire_maintenance_authority',lambda *_a:events.append('retire-old-authority'))
    monkeypatch.setattr(provenance,'reconcile_installed_core',lambda *_a,**_k:events.append('reconcile-core') or 'migrated')
    @contextmanager
    def verified(*_a):yield
    monkeypatch.setattr(msi_inventory,'verified_foundation_bytes',verified)
    for name in ('prepare','before_native','verify_preserved'):
        monkeypatch.setattr(installer_data_security,name,lambda *_a,name=name:events.append('data-'+name))
    class Services:
        def __init__(self,*_a,**_k):pass
        def __enter__(self):return self
        def __exit__(self,*_a):pass
        def assert_quarantined(self):events.append('quarantine')
        def snapshot(self):return {'EndpointAgent':{'start_type':4,'delayed_auto':False},
            'EndpointAgentUpdater':{'start_type':4,'delayed_auto':False},
            'EndpointBrowserPolicy':{'start_type':2,'delayed_auto':False}}
        def quarantine(self,_original,*,recovery=False):events.append('quarantine-browser')
        def restore_final(self):events.append('restore-services')
    monkeypatch.setattr(bridge,'InstallerServices',Services)
    completions=[]
    client=SimpleNamespace(capability=cap,phase='prepare',checkpoint=lambda:events.append('owner'),
        identity=SimpleNamespace(value={'pid':200,'created':2000,'hash':cap['helper_sha256']}),
        request=lambda *args:completions.append(args))
    return paths,client,old,original,native,events,completions


def test_compound_prepare_keeps_old_fence_and_captures_original_before_native(staged):
    paths,client,old,original,native,events,done=staged
    before=(fence.state_root(paths)/'transaction.json').read_bytes()
    bridge.execute_authorized_phase(client,paths)
    assert (fence.state_root(paths)/'transaction.json').read_bytes()==before
    record=plan.read_plan(paths,client.capability)
    assert record['phase']=='prepared' and record['service_startup']==original['service_startup']
    with fence.child_fence(client.capability['transaction_id']):
        child=fence.read_fence(paths)
    assert child['package']['sha256']==client.capability['package']['package_sha256']
    assert child['phase']=='msi-starting' and not child['startup_restored']
    assert 'data-prepare' in events and 'prepare_installer_provenance' in events and 'quarantine' in events
    assert done==[('complete',{'result':'compound-prepared'})]


@pytest.mark.parametrize('defect',['old-absent','new-present','old-owner','old-recovery'])
def test_prepare_rejects_native_or_child_binding_conflict_without_new_evidence(staged,defect):
    paths,client,old,original,native,events,done=staged
    if defect=='old-absent':native[old['package']['product_code']]=-1
    elif defect=='new-present':native[client.capability['package']['product_code']]=5
    else:
        if defect=='old-owner':old['owner']={**old['owner'],'created':1001}
        else:old['recovery']=True
        (fence.state_root(paths)/'capabilities'/(old['session_id']+'.json')).write_text(json.dumps(old))
    with pytest.raises(ValueError):bridge.execute_authorized_phase(client,paths)
    assert not (fence.state_root(paths)/'upgrade.json').exists() and done==[]
    assert 'data-prepare' not in events


def test_child_native_entry_requires_recorded_old_return_and_original_data(staged):
    paths,client,old,original,native,events,done=staged
    bridge.execute_authorized_phase(client,paths)
    client.phase='msi-preflight';done.clear();events.clear()
    with pytest.raises(ValueError):bridge.execute_authorized_phase(client,paths,
        feature_states=(2,3,2,3))
    assert done==[]
    native[old['package']['product_code']]=-1
    client.phase='compound-old-returned'
    bridge.execute_authorized_phase(client,paths)
    assert plan.read_plan(paths,client.capability)['phase']=='old-script-returned'
    client.phase='msi-preflight';events.clear()
    bridge.execute_authorized_phase(client,paths,feature_states=(2,3,2,3))
    assert 'data-before_native' in events and 'validate_interrupted_reconciliation' in events


def test_second_prepare_cannot_recapture_original_state(staged):
    paths,client,*_=staged
    bridge.execute_authorized_phase(client,paths)
    stored=plan._root(paths,client.capability)/'plan.json';before=stored.read_bytes()
    with pytest.raises(ValueError):bridge.execute_authorized_phase(client,paths)
    assert stored.read_bytes()==before


def test_old_foundation_corruption_is_rejected_before_any_new_evidence(staged,monkeypatch):
    paths,client,*_=staged
    def conflict(*_a,**_k):raise ValueError('PROVENANCE_CONFLICT')
    monkeypatch.setattr(msi_inventory,'verify_foundation',conflict)
    with pytest.raises(ValueError):bridge.execute_authorized_phase(client,paths)
    assert not (fence.state_root(paths)/'upgrade.json').exists()


def old_returned(staged):
    paths,client,old,original,native,events,done=staged
    bridge.execute_authorized_phase(client,paths)
    native[old['package']['product_code']]=-1
    original['phase']='msi-executing';original['sequence']=2
    (fence.state_root(paths)/'transaction.json').write_text(json.dumps(original))
    client.phase='compound-old-returned';bridge.execute_authorized_phase(client,paths)
    return paths,client,old,native,events,done


def test_commit_retirement_reconcile_and_finish_keep_barrier_until_final_checks(staged):
    paths,client,old,native,events,done=old_returned(staged)
    native[client.capability['package']['product_code']]=5
    for phase,stored in (('compound-new-returned','new-script-returned'),('compound-commit','committed'),
        ('compound-retire','retired'),('reconcile','reconciled'),('finish','reconciled')):
        client.phase=phase;bridge.execute_authorized_phase(client,paths)
        assert plan.read_plan(paths,client.capability)['phase']==stored
        assert plan.has_active_upgrade(paths)
    assert fence.read_fence(paths) is None
    with fence.child_fence(client.capability['transaction_id']):assert fence.read_fence(paths) is None
    assert 'retire-old-authority' in events and events.index('old-owner-absent')<events.index('retire-old-authority')
    assert events.index('retire-old-authority')<events.index('reconcile-core')<events.index('restore-services')
    client.phase='compound-complete';bridge.execute_authorized_phase(client,paths)
    assert plan.has_active_upgrade(paths)
    archived=plan._root(paths,client.capability)
    assert json.loads((archived/'plan.json').read_text())['phase']=='ready'
    assert done[-1][1]['result']=='compound-ready'
    assert done[-1][1]['marker']['new_transaction_id']==client.capability['transaction_id']
    assert (archived/'old-fence.json').exists()
    assert not (fence.state_root(paths)/'transactions'/old['transaction_id']/'completed.json').exists()


def test_combined_finalization_runs_every_existing_step_before_one_completion(staged):
    paths,client,old,native,events,done=old_returned(staged)
    native[client.capability['package']['product_code']]=5
    client.phase='compound-new-returned';bridge.execute_authorized_phase(client,paths)
    done.clear()
    client.phase='compound-finalize'
    result=bridge.execute_authorized_phase(client,paths)
    assert plan.read_plan(paths,client.capability)['phase']=='ready'
    assert result['result']=='compound-ready'
    assert done==[('complete',result)]
    assert events.index('old-owner-absent')<events.index('retire-old-authority')
    assert events.index('retire-old-authority')<events.index('reconcile-core')<events.index('restore-services')
    assert fence.read_fence(paths) is None
    with fence.child_fence(client.capability['transaction_id']):assert fence.read_fence(paths) is None
    assert len(result['stages'])==5
    assert [row['phase'] for row in result['stages']]==[
        'compound-commit','compound-retire','reconcile','finish','compound-complete']


@pytest.mark.parametrize('failure', ['retire_maintenance_authority','reconcile_installed_core'])
def test_combined_finalization_failure_never_acknowledges_ready(staged,monkeypatch,failure):
    paths,client,old,native,events,done=old_returned(staged)
    native[client.capability['package']['product_code']]=5
    client.phase='compound-new-returned';bridge.execute_authorized_phase(client,paths)
    done.clear()
    def fail(*_a,**_k):raise ValueError('PROVENANCE_CONFLICT')
    monkeypatch.setattr(provenance,failure,fail)
    client.phase='compound-finalize'
    with pytest.raises(ValueError,match='PROVENANCE_CONFLICT'):bridge.execute_authorized_phase(client,paths)
    assert done==[] and plan.read_plan(paths,client.capability)['phase']!='ready'


def test_combined_finalization_is_not_an_early_native_or_recovery_entry(staged):
    paths,client,old,original,native,events,done=staged
    bridge.execute_authorized_phase(client,paths)
    done.clear();client.phase='compound-finalize'
    with pytest.raises(ValueError):bridge.execute_authorized_phase(client,paths)
    assert done==[] and 'retire-old-authority' not in events


@pytest.mark.parametrize('phase',['compound-commit','compound-retire','reconcile','finish','compound-complete'])
def test_early_post_native_phase_cannot_retire_or_enable(staged,phase):
    paths,client,old,native,events,done=old_returned(staged)
    client.phase=phase;events.clear();done.clear()
    before=(fence.state_root(paths)/'transaction.json').read_bytes()
    with pytest.raises(ValueError):bridge.execute_authorized_phase(client,paths)
    assert (fence.state_root(paths)/'transaction.json').read_bytes()==before
    assert 'retire-old-authority' not in events and 'restore-services' not in events and done==[]


def test_successor_api_boundary_requires_installed_new_product(staged):
    paths,client,*_=old_returned(staged)
    client.phase='compound-new-returned'
    with pytest.raises(ValueError):bridge.execute_authorized_phase(client,paths)
    assert plan.read_plan(paths,client.capability)['phase']=='old-script-returned'


def ready_state(staged):
    paths,client,old,native,events,done=old_returned(staged)
    native[client.capability['package']['product_code']]=5
    for phase in ('compound-new-returned','compound-commit','compound-retire','reconcile','finish','compound-complete'):
        client.phase=phase;bridge.execute_authorized_phase(client,paths)
    return paths,client,native,done


def test_compound_verify_settled_requires_exact_owner_marker_and_live_postconditions(staged):
    paths,client,native,done=ready_state(staged)
    marker=done[-1][1]['marker'];done.clear();client.phase='verify-settled'
    with pytest.raises(ValueError):bridge.execute_authorized_phase(client,paths)
    assert done==[]
    history=fence.state_root(paths)/'upgrade-history'/client.capability['compound']['upgrade_id']
    (history/'complete.json').write_text(json.dumps(marker))
    bridge.execute_authorized_phase(client,paths)
    assert done==[('complete',{'settled':True,'selected':client.capability['selected'],'previous':None})]
    done.clear();native[client.capability['package']['product_code']]=-1
    with pytest.raises(ValueError):bridge.execute_authorized_phase(client,paths)
    assert done==[]


def test_failure_after_ready_write_preserves_parent_and_never_acknowledges_completion(staged,monkeypatch):
    paths,client,old,native,events,done=old_returned(staged)
    native[client.capability['package']['product_code']]=5
    for phase in ('compound-new-returned','compound-commit','compound-retire','reconcile','finish'):
        client.phase=phase;bridge.execute_authorized_phase(client,paths)
    original=plan.advance_plan
    def interrupted(*args,**kwargs):
        if args[2]=='ready':raise OSError('ready plan write interrupted')
        return original(*args,**kwargs)
    monkeypatch.setattr(plan,'advance_plan',interrupted)
    client.phase='compound-complete';done.clear()
    with pytest.raises(OSError):bridge.execute_authorized_phase(client,paths)
    assert done==[] and plan.has_active_upgrade(paths)
    assert (fence.state_root(paths)/'upgrade.json').exists()


@pytest.mark.parametrize('mode',['replace-foundation','repair-successor'])
def test_recovery_prepare_preserves_original_proofs_and_uses_new_child_attempt(staged,mode):
    from hashlib import sha256
    from pc_agent.platform.windows.compound_installer import _child
    paths,client,old,original_fence,native,events,done=staged
    bridge.execute_authorized_phase(client,paths)
    original_cap=deepcopy(client.capability);root=fence.state_root(paths)
    (root/'capabilities'/(original_cap['session_id']+'.json')).write_text(json.dumps(original_cap))
    original_plan=plan._root(paths,original_cap)/'plan.json';before=original_plan.read_bytes()
    original_child=root/'children'/original_cap['transaction_id']/'transaction.json';child_before=original_child.read_bytes()
    current=deepcopy(original_cap)
    current.update(owner={**current['owner'],'pid':101,'created':1001},session_id='66666666-6666-4666-8666-666666666666',recovery=True,secret='9'*64)
    current['pipe_name']='EndpointInstaller-'+current['session_id']+'-'+'9'*32
    current['compound']['upgrade_id']='77777777-7777-4777-8777-777777777777'
    current['compound']['recovery']={'original_upgrade_id':original_cap['compound']['upgrade_id'],
        'predecessor_upgrade_id':original_cap['compound']['upgrade_id'],'original_plan_sha256':sha256(before).hexdigest(),
        'predecessor_plan_sha256':sha256(before).hexdigest(),'mode':mode}
    if mode=='replace-foundation':
        old_current=deepcopy(old);old_current.update(owner=current['owner'],recovery=True,session_id='88888888-8888-4888-8888-888888888888',secret='a'*64)
        old_current['pipe_name']='EndpointInstaller-'+old_current['session_id']+'-'+'8'*32
        current['compound']['old']['session_id']=old_current['session_id']
        (root/'capabilities'/(old_current['session_id']+'.json')).write_text(json.dumps(old_current))
    else:
        native[old['package']['product_code']]=-1;native[current['package']['product_code']]=5
    client.capability=current;client.phase='prepare';events.clear();done.clear()
    bridge.execute_authorized_phase(client,paths)
    assert done==[('complete',{'result':'compound-recovery-prepared','mode':mode})]
    assert 'data-prepare' not in events and 'prepare_installer_provenance' not in events
    assert original_plan.read_bytes()==before and original_child.read_bytes()==child_before
    with _child(current):
        assert fence.read_fence(paths)['phase']=='msi-starting'
        assert fence.fence_path(paths).parent.name==current['compound']['upgrade_id']
    assert plan.read_plan(paths,current)['service_startup']==original_fence['service_startup']


@pytest.mark.parametrize('mode',['replace-foundation','repair-successor'])
def test_recovery_full_helper_sequence_keeps_original_and_previous_completion(staged,mode,monkeypatch):
    from pc_agent.platform.windows.compound_installer import _child
    # The fixture's native API/SCM are modeled; actual driver callbacks have
    # compiled-policy tests and installed recovery remains a separate VM gate.
    test_recovery_prepare_preserves_original_proofs_and_uses_new_child_attempt(staged,mode)
    paths,client,old,original,native,events,done=staged
    cap=client.capability;root=fence.state_root(paths)
    original_parent=root/'upgrades'/cap['compound']['recovery']['original_upgrade_id']/'plan.json'
    parent_before=original_parent.read_bytes()
    prior=root/'transactions'/cap['transaction_id']/'completed.json';prior.parent.mkdir(parents=True,exist_ok=True)
    prior.write_bytes(b'preserved previous completed receipt fixture');receipt_before=prior.read_bytes()
    original['phase']='msi-executing';original['sequence']=2
    (root/'transaction.json').write_text(json.dumps(original))
    if mode=='replace-foundation':
        native[old['package']['product_code']]=-1
        client.phase='compound-old-returned';bridge.execute_authorized_phase(client,paths)
    for name in ('enter_native','configure'):
        monkeypatch.setattr(installer_data_security,name,lambda *_a,name=name:events.append('data-'+name))
    for phase in ('msi-preflight','recover-enter','foundation-config','msi-complete'):
        client.phase=phase;bridge.execute_authorized_phase(client,paths,feature_states=(2,3,2,3))
    configured=['configure_service_sids','data-configure','apply_tray_status_acl','restrict_updater_start_permissions']
    assert [e for e in events if e in configured]==configured
    native[cap['package']['product_code']]=5
    monkeypatch.setattr(provenance,'retire_replaced_maintenance_authority',lambda *_a:events.append('retire-replaced'))
    phases=(('compound-new-returned','compound-commit') if mode=='replace-foundation' else
        ('compound-repair-returned','compound-repair-commit'))
    for phase in (*phases,'compound-retire','reconcile','finish','compound-complete'):
        client.phase=phase;bridge.execute_authorized_phase(client,paths)
        assert plan.has_active_upgrade(paths)
    assert original_parent.read_bytes()==parent_before and prior.read_bytes()==receipt_before
    assert bridge.completion_root(paths,cap).parent.name=='attempts'
    assert bridge.completion_root(paths,cap).joinpath('completed.json').exists()
    with _child(cap):assert fence.read_fence(paths) is None
    assert done[-1][1]['result']=='compound-ready' and 'retire-replaced' in events
