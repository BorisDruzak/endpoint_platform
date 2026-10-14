"""A completed helper is readiness, never the owner's final commit."""
from hashlib import sha256
import json

import pytest

from pc_agent.platform.windows import compound_upgrade_plan as plan, installer_fence as fence
from pc_agent.platform.windows.update_paths import WindowsUpdatePaths
from pc_agent.tests.windows.test_compound_upgrade_plan import inputs


@pytest.fixture
def terminal(tmp_path, monkeypatch, inputs):
    paths=WindowsUpdatePaths(tmp_path/'Agent',tmp_path/'data/updates/pending_update.json')
    root=fence.state_root(paths);root.mkdir()
    monkeypatch.setattr(fence,'assert_state_security',lambda *_a,**_k:None)
    cap,old,original=inputs
    record=plan.make_plan(cap,old,original)
    barrier=plan._barrier(record)
    history=root/'upgrade-history'/barrier['upgrade_id'];history.mkdir(parents=True)
    ready={**barrier,'successor_product_code':cap['package']['product_code'],
        'source_revision':cap['package']['source_revision'],'phase':'ready'}
    raw=json.dumps(ready,sort_keys=True,separators=(',',':')).encode('ascii')
    marker={key:value for key,value in ready.items() if key!='phase'}
    marker['ready_sha256']=sha256(raw).hexdigest()
    for path,value in ((root/'upgrade.json',barrier),(history/'barrier.json',barrier)):
        path.write_text(json.dumps(value),encoding='ascii')
    (history/'ready.json').write_bytes(raw)
    return paths,history,marker


def test_ready_receipt_without_owner_publication_keeps_launch_excluded(terminal):
    paths,history,marker=terminal
    assert plan.has_active_upgrade(paths)
    with pytest.raises(ValueError,match='INSTALLER_RECOVERY_REQUIRED'):fence.assert_launch_allowed(paths)


def test_positive_commit_is_exact_and_does_not_depend_on_current_ota_selector(terminal):
    paths,history,marker=terminal
    (history/'complete.json').write_text(json.dumps(marker),encoding='ascii')
    assert not plan.has_active_upgrade(paths)
    fence.assert_launch_allowed(paths)
    # Historical terminal authority survives normal subsequent OTA selection.
    (paths.install_root).mkdir()
    (paths.install_root/'current.json').write_text('{"changed":"by later OTA"}')
    assert not plan.has_active_upgrade(paths)


@pytest.mark.parametrize('defect',['digest','upgrade','product','source','extra','torn','security','link'])
def test_invalid_or_stale_publication_never_admits_launch(terminal,monkeypatch,defect):
    paths,history,marker=terminal
    if defect=='digest':marker['ready_sha256']='0'*64
    elif defect=='upgrade':marker['upgrade_id']='66666666-6666-4666-8666-666666666666'
    elif defect=='product':marker['successor_product_code']='{66666666-6666-4666-8666-666666666666}'
    elif defect=='source':marker['source_revision']='0'*40
    elif defect=='extra':marker['complete']=True
    path=history/'complete.json';path.write_text(json.dumps(marker),encoding='ascii')
    if defect=='torn':path.write_bytes(b'{')
    elif defect=='security':
        def denied(target,**_k):
            if target==path:raise ValueError('UPDATE_STATE_INVALID')
        monkeypatch.setattr(fence,'assert_state_security',denied)
    elif defect=='link':(history/'alias.json').hardlink_to(path)
    with pytest.raises(ValueError):fence.assert_launch_allowed(paths)


def test_missing_active_pointer_with_retained_lifecycle_is_fail_closed(terminal):
    paths,history,marker=terminal
    (history/'complete.json').write_text(json.dumps(marker),encoding='ascii')
    (fence.state_root(paths)/'upgrade.json').unlink()
    assert plan.has_active_upgrade(paths)
    with pytest.raises(ValueError,match='INSTALLER_RECOVERY_REQUIRED'):fence.assert_launch_allowed(paths)


def test_successor_barrier_cannot_reuse_previous_marker(terminal):
    paths,history,marker=terminal
    (history/'complete.json').write_text(json.dumps(marker),encoding='ascii')
    barrier=json.loads((fence.state_root(paths)/'upgrade.json').read_text())
    barrier['upgrade_id']='66666666-6666-4666-8666-666666666666'
    (fence.state_root(paths)/'upgrade.json').write_text(json.dumps(barrier))
    assert plan.has_active_upgrade(paths)


@pytest.mark.parametrize('defect',[None,'uninstall','stale-history','receipt-changed','incomplete','different-package'])
def test_standalone_reinstall_requires_authenticated_completed_lifecycle(terminal,inputs,defect):
    from pc_agent.tests.windows.test_installer_fence import state
    paths,history,marker=terminal
    (history/'complete.json').write_text(json.dumps(marker))
    package={**inputs[0]['package'],'package_sha256':'9'*64,'version':'3.2.95','source_revision':'8'*40}
    transaction='77777777-7777-4777-8777-777777777777'
    completed=state();completed.update(transaction_id=transaction,operation='install',phase='complete',startup_restored=True)
    completed['package'].update(sha256=package['package_sha256'],version=package['version'],source_revision=package['source_revision'],product_code=package['product_code'])
    receipt=fence.state_root(paths)/'transactions'/transaction/'completed.json';receipt.parent.mkdir(parents=True)
    raw=json.dumps(completed).encode();receipt.write_bytes(raw)
    lifecycle={'schema_version':1,'transaction_id':transaction,'operation':'install','package':package,
        'previous_upgrade_id':marker['upgrade_id'],'previous_ready_sha256':marker['ready_sha256'],
        'receipt_sha256':sha256(raw).hexdigest()}
    if defect=='uninstall':lifecycle['operation']='uninstall'
    elif defect=='stale-history':lifecycle['previous_upgrade_id']=transaction
    elif defect=='receipt-changed':receipt.write_bytes(raw+b' ')
    elif defect=='incomplete':
        completed['startup_restored']=False;raw=json.dumps(completed).encode();receipt.write_bytes(raw);lifecycle['receipt_sha256']=sha256(raw).hexdigest()
    elif defect=='different-package':lifecycle['package']={**package,'version':'3.2.96'}
    (fence.state_root(paths)/'standalone-lifecycle.json').write_text(json.dumps(lifecycle))
    if defect is None:plan.validate_standalone_predecessor(paths,package,marker)
    else:
        with pytest.raises(ValueError):plan.validate_standalone_predecessor(paths,package,marker)


def test_ordinary_finish_records_completed_receipt_before_fence_retirement(terminal,inputs,monkeypatch):
    from pc_agent.tests.windows.test_installer_fence import state
    paths,history,marker=terminal
    (history/'complete.json').write_text(json.dumps(marker))
    cap={key:value for key,value in inputs[0].items() if key!='compound'}
    cap['package']={**cap['package'],'package_sha256':'9'*64,'version':'3.2.95'}
    completed=state();completed.update(transaction_id=cap['transaction_id'],operation='install',phase='complete',startup_restored=True)
    completed['package'].update(sha256=cap['package']['package_sha256'],version=cap['package']['version'],source_revision=cap['package']['source_revision'],product_code=cap['package']['product_code'])
    receipt=fence.state_root(paths)/'transactions'/cap['transaction_id']/'completed.json';receipt.parent.mkdir(parents=True);receipt.write_text(json.dumps(completed))
    monkeypatch.setattr(fence,'protect_state',lambda *_a,**_k:None)
    plan.record_standalone_completion(paths,cap,completed)
    plan.validate_standalone_predecessor(paths,cap['package'],marker)
    assert not plan.has_active_upgrade(paths)


def test_compound_uninstall_reinstall_then_upgrade_preserves_original_history(terminal,inputs,monkeypatch):
    from copy import deepcopy
    from pc_agent.tests.windows.test_installer_fence import state
    paths,history,marker=terminal
    original_marker=json.dumps(marker).encode();(history/'complete.json').write_bytes(original_marker)
    original_ready=(history/'ready.json').read_bytes()
    monkeypatch.setattr(fence,'protect_state',lambda *_a,**_k:None)
    cap,old,old_fence=deepcopy(inputs)
    c={**old['package'],'package_sha256':'9'*64,'version':'3.2.95','source_revision':'8'*40}
    for operation,package,transaction in (('uninstall',cap['package'],'77777777-7777-4777-8777-777777777777'),
        ('install',c,'88888888-8888-4888-8888-888888888888')):
        standalone={key:value for key,value in cap.items() if key!='compound'}
        standalone.update(operation=operation,package=package,transaction_id=transaction)
        completed=state();completed.update(transaction_id=transaction,operation=operation,phase='complete',startup_restored=True)
        completed['package'].update(sha256=package['package_sha256'],version=package['version'],source_revision=package['source_revision'],product_code=package['product_code'])
        path=fence.state_root(paths)/'transactions'/transaction/'completed.json';path.parent.mkdir(parents=True);path.write_text(json.dumps(completed))
        plan.record_standalone_completion(paths,standalone,completed)
        if operation=='uninstall':
            with pytest.raises(ValueError):plan.validate_standalone_predecessor(paths,c,marker)
    old.update(package=c,transaction_id='99999999-9999-4999-8999-999999999999',session_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')
    cap.update(transaction_id='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',session_id='cccccccc-cccc-4ccc-8ccc-cccccccccccc')
    cap['package'].update(version='3.2.96',package_sha256='6'*64,product_code='{66666666-6666-4666-8666-666666666666}')
    cap['compound']={'upgrade_id':'dddddddd-dddd-4ddd-8ddd-dddddddddddd','old':{key:old[key] for key in plan._BINDING}}
    old_fence.update(transaction_id=old['transaction_id'])
    old_fence['package'].update(sha256=c['package_sha256'],version=c['version'],source_revision=c['source_revision'],product_code=c['product_code'])
    record=plan.make_plan(cap,old,old_fence)
    plan.publish_plan(paths,cap,record)
    assert plan.read_plan(paths,cap)==record and plan.has_active_upgrade(paths)
    assert (history/'complete.json').read_bytes()==original_marker
    assert (history/'ready.json').read_bytes()==original_ready
    assert plan._read(plan._root(paths,cap)/'predecessor.json',secret=True)==marker
