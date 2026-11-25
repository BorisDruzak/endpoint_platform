"""A new owner may resume exact original facts, never replace their baseline."""
from copy import deepcopy
from hashlib import sha256
import json
from types import SimpleNamespace

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


@pytest.mark.parametrize('role,phase,plan_phase,held', [
    ('new', 'prepared', 'prepared', False),
    ('new', 'msi-starting', 'prepared', True),
    ('old', 'msi-starting', 'prepared', True),
    ('new', 'msi-executing', 'old-script-returned', True),
    ('new', 'msi-executing', 'prepared', True),
    ('old', 'msi-executing', 'prepared', True),
    ('new', 'msi-starting', 'old-script-returned', True),
    ('new', 'msi-executing', 'committed', False),
])
def test_original_child_outcome_gates_compound_recovery(stored_recovery, monkeypatch, role, phase, plan_phase, held):
    from pc_agent.platform.windows import installer_transaction_bridge as bridge, msi_inventory, setup_entry
    from pc_agent.tests.windows.test_installer_fence import state

    paths, cap, record, original_root, _ = stored_recovery
    original = json.loads((original_root/'plan.json').read_bytes())
    original_cap = bridge._read_capability(paths, original['new']['session_id'])
    original_cap['service_states'] = {'EndpointAgent':'running', 'EndpointAgentUpdater':'stopped'}
    for step in ('old-script-returned','new-script-returned','committed')[:('prepared','old-script-returned','new-script-returned','committed').index(plan_phase)]:
        plan.advance_plan(paths, original_cap, step, native_result=0)
    state_root = plan.installer_fence.state_root(paths)
    leaf = (state_root/'children'/original['new']['transaction_id'] if role == 'new' else state_root)/'transaction.json'
    leaf.parent.mkdir(parents=True, exist_ok=True)
    value = state()
    value.update(transaction_id=original[role]['transaction_id'], phase=phase,
                 operation='uninstall' if role == 'old' else 'install',
                 sequence=2 if phase == 'msi-executing' else 1, selected=original['selected'],
                 service_states=original_cap['service_states'], service_startup=original['service_startup'])
    target = original[role]['package']
    value['package'].update(sha256=target['package_sha256'], version=target['version'],
                            source_revision=target['source_revision'], product_code=target['product_code'])
    leaf.write_text(json.dumps(value))
    files = (leaf, original_root/'plan.json', plan.installer_fence.state_root(paths)/'upgrade.json')
    snapshot = [item.read_bytes() for item in files]
    result = plan.inspect_recovery_authority(paths, cap['package'])
    assert bool(result.get('msi_outcome_unconfirmed')) is held
    assert result['transaction_id'] == original['new']['transaction_id']
    manifest = original_root/'fixture.release.json'
    manifest.write_text(json.dumps(cap['package']))
    monkeypatch.setattr(setup_entry, '_verify_embedded_msi', lambda _: (manifest, None))
    monkeypatch.setattr(setup_entry.WindowsUpdatePaths, 'production', lambda: paths)
    if held:
        with pytest.raises(setup_entry.SetupInstallError) as raised:
            setup_entry._embedded_recovery_operation(leaf)
        assert raised.value.detail == 'MSI_OUTCOME_UNCONFIRMED'
        messages = []
        request = {
            'package': cap['package'], 'helper_sha256': original['new']['helper_sha256'],
            'transaction_id': original['new']['transaction_id'], 'recovery_parent': original['upgrade_id'],
        }
        client = SimpleNamespace(phase='inspect-compound', capability=request,
                                 request=lambda *args: messages.append(args))
        monkeypatch.setattr(msi_inventory, 'NativeMsi', lambda: pytest.fail('must not infer a recovery mode'))
        assert bridge.execute_authorized_phase(client, paths) == result
        assert messages == [('complete', result)]
        from pc_agent.platform.windows import compound_installer
        captured = json.loads(snapshot[1])
        monkeypatch.setattr(plan, 'read_recovery_original',
                            lambda *_: (captured, snapshot[1], original_cap))
        monkeypatch.setattr(plan, '_read_recovery_predecessor',
                            lambda *_: captured)
        with pytest.raises(ValueError, match='MSI_OUTCOME_UNCONFIRMED'):
            compound_installer._prepare_recovery(SimpleNamespace(capability=cap), paths, None)
    else:
        assert setup_entry._embedded_recovery_operation(leaf) == 'install'
    assert [item.read_bytes() for item in files] == snapshot


@pytest.mark.parametrize('staged_phase,attempt_exit,armed,held', [
    ('switching', None, False, False),  # Durable compound plan exists before arming.
    ('switching', None, True, True),   # Old API can be active before either callback.
    ('switching', 0, True, True),      # A success code contradicts the uncommitted plan.
    ('accepted', None, False, True),   # Staged terminal cannot prove MSI End.
])
def test_staged_attempt_precedes_deferred_msi_markers(
        stored_recovery, monkeypatch, staged_phase, attempt_exit, armed, held):
    from pc_agent.platform.windows import (
        installation_provenance, installer_transaction_bridge as bridge, staged_recovery,
        staged_update_state as state,
    )
    from pc_agent.tests.windows.test_installer_fence import state as fence_state

    paths, _, _, original_root, raw = stored_recovery
    original = json.loads(raw)
    cap = bridge._read_capability(paths, original['new']['session_id'])
    cap['service_states'] = {'EndpointAgent': 'running', 'EndpointAgentUpdater': 'stopped'}
    target = original['new']
    binding = state.StagedUpdateBinding(
        target['transaction_id'], original['old']['package'], target['package'],
        json.dumps({'schema_version': 1, 'version': original['old']['package']['version'],
                    'source_revision': original['old']['package']['source_revision']}).encode(),
        None, 'a' * 64, None, target['package']['version'],
        target['package']['source_revision'], 'b' * 64,
    )
    stage = state.StagedUpdateRecord(binding, staged_phase, 2, None, original['owner'], None, None)
    monkeypatch.setattr(state, 'read_staged_update', lambda _: stage)
    monkeypatch.setattr(installation_provenance, '_assert_security', lambda *_: None)
    old = original['old']
    prior = old['package']
    fence = fence_state()
    fence.update(phase='msi-starting', operation='uninstall', transaction_id=old['transaction_id'],
                 selected=original['selected'], service_states=cap['service_states'],
                 service_startup=original['service_startup'])
    fence['package'].update(sha256=prior['package_sha256'], source_revision=prior['source_revision'],
                            version=prior['version'], product_code=prior['product_code'])
    root = plan.installer_fence.state_root(paths)
    (root/'transaction.json').write_text(json.dumps(fence))
    if armed:
        leaf = staged_recovery._root(paths, binding.operation_id)/'reboot.json'
        leaf.parent.mkdir(parents=True)
        leaf.write_text(json.dumps({
            'schema_version': 2, 'binding_sha256': staged_recovery._binding_hash(stage),
            'attempt_id': '11111111-1111-4111-8111-111111111111', 'owner': original['owner'],
            'native_exit': attempt_exit, 'boot': 'registry-boot-v1:22222222-2222-4222-8222-222222222222',
        }))
    result = plan.inspect_recovery_authority(paths, target['package'])
    assert bool(result.get('msi_outcome_unconfirmed')) is held
    assert (original_root/'plan.json').read_bytes() == raw


@pytest.mark.parametrize("child_phase, foreign_receipt, expected", [
    ("msi-executing", False, 21),
    ("msi-starting", False, 61),
    ("msi-executing", True, 61),
])
def test_ordinary_setup_holds_exact_original_compound_attempt(
    stored_recovery, monkeypatch, tmp_path, child_phase, foreign_receipt, expected,
):
    from contextlib import nullcontext
    from datetime import UTC, datetime

    from pc_agent.platform.windows import (
        installation_provenance, installer_transaction_bridge, setup_entry, staged_recovery,
        staged_update_state as state, update_transaction,
    )
    from pc_agent.tests.windows.test_installer_fence import state as fence_state

    paths, _, _, original_root, raw = stored_recovery
    original = json.loads(raw)
    capability = installer_transaction_bridge._read_capability(paths, original["new"]["session_id"])
    capability["service_states"] = {"EndpointAgent": "running", "EndpointAgentUpdater": "stopped"}
    old_release = original["old"]["package"]
    release = original["new"]["package"]
    operation = original["new"]["transaction_id"]
    paths.install_root.mkdir()
    paths.updates_root.mkdir(parents=True)
    selected = json.dumps({
        "schema_version": 1, "version": old_release["version"], "source_revision": old_release["source_revision"],
    }).encode()
    binding = state.StagedUpdateBinding(
        operation, old_release, release, selected, None, "a" * 64, None,
        release["version"], release["source_revision"], "b" * 64,
    )
    staged = state.StagedUpdateRecord(binding, "switching", 2, None, original["owner"], datetime.now(UTC), None)
    state._path(paths).write_text(json.dumps(state._record_value(staged)), encoding="utf-8")
    paths.current_path.write_bytes(b"\0" * len(selected))
    attempt = staged_recovery._root(paths, operation) / "reboot.json"
    attempt.parent.mkdir(parents=True)
    attempt.write_text(json.dumps({
        "schema_version": 2,
        "binding_sha256": "1" * 64 if foreign_receipt else staged_recovery._binding_hash(staged),
        "attempt_id": "11111111-1111-4111-8111-111111111111", "owner": original["owner"],
        "native_exit": None, "boot": "registry-boot-v1:22222222-2222-4222-8222-222222222222",
    }), encoding="utf-8")
    with plan.installer_fence.child_fence(operation):
        child = plan.installer_fence.fence_path(paths)
    child.parent.mkdir(parents=True)
    fence = fence_state()
    fence.update(
        transaction_id=operation, phase=child_phase, sequence=2, selected=original["selected"],
        previous=original["previous"], service_startup=original["service_startup"],
    )
    fence["package"].update(
        sha256=release["package_sha256"], product_code=release["product_code"],
        version=release["version"], source_revision=release["source_revision"],
    )
    child.write_text(json.dumps(fence), encoding="utf-8")
    manifest = tmp_path / "EndpointAgent.release.json"
    manifest.write_text(json.dumps(release), encoding="utf-8")
    diagnostics = tmp_path / "diagnostics"

    def snapshot():
        return {item: item.read_bytes() for item in tmp_path.rglob("*") if item.is_file()
                and not item.is_relative_to(diagnostics)}

    before = snapshot()
    monkeypatch.setattr(setup_entry, "WindowsUpdatePaths", lambda **_: paths)
    monkeypatch.setattr(setup_entry, "_data_root", lambda: paths.updates_root.parent)
    monkeypatch.setattr(setup_entry, "_resource_root", lambda: tmp_path)
    monkeypatch.setattr(setup_entry, "_diagnostics_root", lambda: diagnostics)
    monkeypatch.setattr(setup_entry, "_verify_embedded_msi", lambda _: (manifest, None))
    monkeypatch.setattr(staged_recovery, "_assert_owner_dead", lambda _: None)
    monkeypatch.setattr(installation_provenance, "_assert_security", lambda _: None)
    monkeypatch.setattr(update_transaction, "_assert_install_directory_security", lambda _: None)
    monkeypatch.setattr(update_transaction, "_assert_state_security", lambda _: None)
    monkeypatch.setattr(update_transaction, "_windows_transaction", lambda timeout_ms: nullcontext())
    for name in ("_record_in_progress", "_install_embedded_msi", "_require_setup_disk", "_agent_service_installed"):
        monkeypatch.setattr(setup_entry, name, lambda *_a, name=name: pytest.fail(f"unexpected {name}"))

    if not foreign_receipt:
        assert state.read_staged_update(paths) == staged
        assert staged_recovery._native_attempt(paths, staged)["native_exit"] is None
        assert plan.inspect_recovery_authority(paths, release)["msi_outcome_unconfirmed"]
        with plan.installer_fence.child_fence(operation):
            assert plan.installer_fence.read_fence(paths) == fence
        assert update_transaction.active_update_state(paths) is None
    assert setup_entry.main(["--quiet"]) == expected
    result = json.loads((diagnostics / "install-result.json").read_bytes())
    assert result["detail"] == ("MSI_OUTCOME_UNCONFIRMED" if expected == 21 else "UPDATE_IN_PROGRESS")
    assert snapshot() == before


@pytest.mark.parametrize('defect', [
    'torn', 'valid-but-different', 'foreign-copy', 'advanced-copy', 'unsafe-primary',
])
def test_recovery_can_use_only_a_bound_prepared_copy_after_a_parse_failure(
        stored_recovery, monkeypatch, defect):
    from pc_agent.platform.windows import installer_fence as fence, installer_transaction_bridge as bridge

    paths, attempt, next_record, root, raw = stored_recovery
    captured = json.loads(raw)
    cap = bridge._read_capability(paths, captured['new']['session_id'])
    cap['service_states'] = {'EndpointAgent': 'stopped', 'EndpointAgentUpdater': 'stopped'}
    plan.publish_plan(paths, cap, captured)
    prepared = root / 'prepared-plan.json'
    current = root / 'plan.json'
    assert prepared.read_bytes() == raw
    plan.advance_plan(paths, cap, 'old-script-returned', native_result=0)
    assert prepared.read_bytes() == raw
    assert plan.read_plan(paths, cap)['phase'] == 'old-script-returned'

    if defect == 'valid-but-different':
        current.write_text(json.dumps({**captured, 'selected': 'a' * 64}))
    else:
        current.write_bytes(b'INDX' + b'\0' * 64)
    if defect in ('foreign-copy', 'advanced-copy'):
        bad = ({**captured, 'selected': 'a' * 64} if defect == 'foreign-copy' else
               {**captured, 'phase': 'old-script-returned', 'sequence': 1})
        prepared.write_text(json.dumps(bad))
    if defect == 'unsafe-primary':
        def reject_acl(path, **_kwargs):
            if path == current:
                raise ValueError('UPDATE_STATE_INVALID')
        monkeypatch.setattr(fence, 'assert_state_security', reject_acl)

    damaged = current.read_bytes()
    with pytest.raises(ValueError):
        plan.read_plan(paths, cap)
    if defect == 'torn':
        recovered = plan.inspect_recovery_authority(paths, cap['package'])
        assert recovered['original_plan_sha256'] == recovered['predecessor_plan_sha256'] == sha256(raw).hexdigest()
        assert plan.has_active_upgrade(paths)
        plan.publish_recovery_plan(paths, attempt, next_record)
        assert plan.read_plan(paths, attempt) == next_record
    else:
        with pytest.raises(ValueError):
            plan.inspect_recovery_authority(paths, cap['package'])
        assert plan.has_active_upgrade(paths)
    assert current.read_bytes() == damaged


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
