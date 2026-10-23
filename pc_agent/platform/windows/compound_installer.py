"""Fixed successor-helper phases for an authenticated foundation replacement.

The immutable predecessor keeps its own capability/global fence. This module
never runs MSI, acquires the mutex or treats native product absence as entry.
The live owner separately grants each API-return and delayed-commit boundary.
"""
from pathlib import Path
import time

from endpoint_contracts.runtime_payload import read_json

from . import compound_upgrade_plan as plan, durable_state, installer_fence as fence
from . import installation_provenance as provenance, installer_data_security, msi_inventory


def _fail():
    raise ValueError('PROVENANCE_CONFLICT')


def _data_request(paths,capability):
    from .installer_transaction_bridge import _request_data
    return {**_request_data(paths,capability),'session_id':capability['session_id'],'recovery':capability['recovery']}


def _child(capability):
    return fence.child_fence(capability['transaction_id'],attempt_id=(
        capability['compound']['upgrade_id'] if capability['recovery'] else None))


def _old_capability(paths,capability):
    from .installer_transaction_bridge import _read_capability
    old=_read_capability(paths,capability['compound']['old']['session_id'])
    recovering=capability['recovery']
    historical=recovering and capability['compound']['recovery']['mode']=='repair-successor'
    owner=capability['owner']
    prepared='prepared_old' in capability['compound']
    if prepared:plan.read_prepared_source(paths,capability)
    if historical:
        original,_raw,_cap=plan.read_recovery_original(paths,capability)
        owner=original['owner']
    if ('compound' in old or old['recovery'] is not (prepared or (recovering and not historical)) or old['uninstall_finalization'] is not False
        or old['operation']!='uninstall' or old['owner']!=owner
        or {key:old[key] for key in plan._BINDING}!=capability['compound']['old']
        or any(old[key]!=capability[key] for key in ('selected','previous'))):
        _fail()
    return old


def _old_request(paths,capability):
    from .installer_transaction_bridge import _request_data
    return _request_data(paths,_old_capability(paths,capability))


def _native_products(capability,*,new_state=None):
    native=msi_inventory.NativeMsi()
    if native.product(capability['compound']['old']['package']['product_code'])!=-1:
        _fail()
    if new_state is not None and native.product(capability['package']['product_code'])!=new_state:
        _fail()


def validate_native_intermediate(paths,capability,expected):
    """Only original archives plus exact package bytes survive old removal."""
    record=plan.read_plan(paths,capability)
    allowed={'old-script-returned','new-script-returned','committed','retired'}
    if record.get('recovery',{}).get('mode')=='repair-successor':allowed={'prepared','repair-script-returned','repair-committed','retired'}
    if record['phase'] not in allowed:
        _fail()
    _native_products(capability)
    from .installer_transaction_bridge import _request_data
    request=_request_data(paths,capability)
    native=msi_inventory.read_native_selector(request['package_path'],expected)
    provenance.validate_interrupted_reconciliation(paths,request,native_current=native,
        allow_native_absence=record['phase']=='old-script-returned')


def _verify_successor(paths,capability,expected):
    _native_products(capability,new_state=5)
    msi_inventory.verify_installed(expected.package,paths.install_root)
    with msi_inventory.verified_foundation_bytes(expected,paths.install_root):pass
    installer_data_security.verify_preserved(paths,_data_request(paths,capability))


def _prepare_recovery(client,paths,expected):
    from . import installer_transaction_bridge as bridge
    cap=client.capability
    original,raw,original_cap=plan.read_recovery_original(paths,cap)
    record=plan.make_recovery_plan(cap,original,raw,original_cap)
    old=_old_capability(paths,cap)
    mode=record['recovery']['mode'];native=msi_inventory.NativeMsi()
    states=(native.product(old['package']['product_code']),native.product(cap['package']['product_code']))
    if states!=((5,-1) if mode=='replace-foundation' else (-1,5)):_fail()
    # This observation chooses native work. It authorizes no retirement/startup.
    # The actual serialized script, delayed callback and End remain mandatory.
    request=bridge._request_data(paths,cap)
    if mode=='replace-foundation':
        old_request=bridge._request_data(paths,old)
        old_expected=msi_inventory.read_expected_package(old_request['package_path'],old['package'])
        msi_inventory.verify_foundation(old_expected.package,paths.install_root,expected=old_expected)
        active=fence.read_fence(paths)
        if active is None or active['transaction_id']!=old['transaction_id']:_fail()
        provenance.validate_interrupted_reconciliation(paths,request)
    else:
        provenance.validate_interrupted_reconciliation(paths,request,
            native_current=msi_inventory.read_native_selector(request['package_path'],expected))
    data_request = _data_request(paths,cap)
    installer_data_security.restore_native_rollback_inheritance(paths,data_request)
    installer_data_security.before_native(paths,data_request)
    if cap['service_states']!=original_cap['service_states']:_fail()
    with bridge.InstallerServices(paths,include_browser=True,checkpoint=client.checkpoint) as services:
        current=services.snapshot()
        if any(value is None for value in current.values()):_fail()
        services.quarantine(current,recovery=True)
    plan.publish_recovery_plan(paths,cap,record)
    parent=fence.state_root(paths)
    for name in ('children',cap['transaction_id'],cap['compound']['upgrade_id']):
        parent=provenance._archive_directory(parent,name)
    with _child(cap):
        if fence.read_fence(paths) is not None:_fail()
        fence.publish_fence(paths,bridge._public_fence(expected,cap,record['service_startup']))
        bridge._advance_fence(paths,client,expected,'msi-starting')
    return {'result':'compound-recovery-prepared','mode':mode}


class _FinalizationStep:
    """Fixed logical steps share one authenticated post-commit peer.

    Mutation grants still go to the original outer phase. Intermediate logical
    completions are not sent to the owner; only the final verified ready marker
    can acknowledge the combined phase.
    """
    def __init__(self, client, phase):
        self.outer = client
        self.phase = phase
        self.completed = False

    def __getattr__(self, name):
        return getattr(self.outer, name)

    def request(self, action, payload=None):
        if action == 'complete':
            if self.completed:
                _fail()
            self.completed = True
            return None
        return self.outer.request(action, payload)


def _finalize_compound(client, paths):
    cap = client.capability
    if cap['recovery'] or plan.read_plan(paths, cap)['phase'] != 'new-script-returned':
        _fail()
    _native_products(cap, new_state=5)
    from . import installer_transaction_bridge as bridge
    request = bridge._request_data(paths, cap)
    expected = msi_inventory.read_expected_package(request['package_path'], cap['package'])
    # Preserve the active physical peer for owner-loss recovery before the long
    # read-only verification. Native End(Commit) admission belongs to the owner.
    with durable_state.installer_mutation_checkpoints(client.checkpoint), _child(cap):
        bridge._advance_fence(paths, client, expected, 'msi-returned')
    with msi_inventory.immutable_foundation_reads(expected, paths.install_root):
        stages = []
        for phase in ('compound-commit', 'compound-retire', 'reconcile', 'finish', 'compound-complete'):
            step = _FinalizationStep(client, phase)
            started = time.perf_counter()
            result = execute_compound_phase(step, paths)
            if not step.completed:
                _fail()
            stages.append({'phase': phase, 'seconds': round(time.perf_counter()-started, 6)})
        if result.get('result') != 'compound-ready':
            _fail()
        result = {**result, 'stages': stages}
        client.request('complete', result)
    return result


def execute_compound_phase(client,paths,*,feature_states=None,rollback_disabled='',uninstall_finalization=''):
    from . import installer_transaction_bridge as bridge
    cap=client.capability
    plan._capability_binding(cap)
    if uninstall_finalization or cap['operation']!='install':
        _fail()
    phase=client.phase
    if phase == 'compound-finalize':
        return _finalize_compound(client, paths)
    request=bridge._request_data(paths,cap)
    data_request=_data_request(paths,cap)
    expected=msi_inventory.read_expected_package(request['package_path'],cap['package'])
    if phase=='verify-settled':
        bridge._settled(paths)
        record=plan.read_plan(paths,cap)
        marker=plan.committed_marker(paths)
        if record['phase']!='ready' or marker is None or any(marker[key]!=value for key,value in plan._barrier(record).items()):_fail()
        if fence.read_fence(paths) is not None:_fail()
        with _child(cap):
            if fence.read_fence(paths) is not None:_fail()
        _verify_successor(paths,cap,expected)
        inspected=provenance.inspect_installed_core(paths,resulting_foundation=expected.package.version)
        result={'settled':True,**bridge._digests(inspected)}
        client.request('complete',result)
        return result
    if phase in {'msi-preflight','msi-enter','recover-enter','foundation-config','msi-complete'}:
        validate_native_intermediate(paths,cap,expected)
        with _child(cap):
            return bridge._execute_authorized_phase(client,paths,feature_states=feature_states,
                rollback_disabled=rollback_disabled,uninstall_finalization=uninstall_finalization)
    result={}
    with durable_state.installer_mutation_checkpoints(client.checkpoint):
        bridge._settled(paths)
        if phase=='prepare':
            if cap['recovery']:
                result=_prepare_recovery(client,paths,expected)
                client.request('complete',result)
                return result
            if plan.has_active_upgrade(paths):
                raise ValueError('UPDATE_IN_PROGRESS')
            old=_old_capability(paths,cap)
            original=fence.read_fence(paths)
            if original is None or original['phase']!='msi-starting':
                _fail()
            native=msi_inventory.NativeMsi()
            if native.product(old['package']['product_code'])!=5 or native.product(cap['package']['product_code'])!=-1:
                _fail()
            old_request=bridge._request_data(paths,old)
            old_expected=msi_inventory.read_expected_package(old_request['package_path'],old['package'])
            msi_inventory.verify_foundation(old_expected.package,paths.install_root,expected=old_expected)
            with bridge.InstallerServices(paths) as services:
                services.assert_quarantined()
            with bridge.InstallerServices(paths,include_browser=True) as services:
                actual_startup=services.snapshot()
            if actual_startup['EndpointBrowserPolicy'] is None: _fail()
            prepared_source=None
            if 'prepared_old' in cap['compound']:
                prepared_source,saved_fence,saved_maintenance=plan.read_prepared_source(paths,cap)
                if saved_fence!=original:_fail()
                actual_maintenance=provenance.validate_maintenance_recovery(paths,old_request,'uninstall')
                if actual_maintenance!=saved_maintenance:_fail()
            record=plan.make_plan(cap,old,original,browser_startup=actual_startup['EndpointBrowserPolicy'],prepared_source=prepared_source)
            # The successor has not begun native work. Its original before-state
            # is captured while genuine old ownership still verifies completely.
            from .installation_provenance import inspect_installed_core
            inspected=inspect_installed_core(paths,resulting_foundation=expected.package.version)
            if bridge._digests(inspected)!={key:cap[key] for key in ('selected','previous')}:
                _fail()
            installer_data_security.prepare(paths,data_request)
            provenance.prepare_installer_provenance(paths,request)
            provenance.validate_interrupted_reconciliation(paths,request)
            plan.publish_plan(paths,cap,record)
            with bridge.InstallerServices(paths,include_browser=True,checkpoint=client.checkpoint) as services:
                services.quarantine(actual_startup)
            root=provenance._archive_directory(provenance._archive_directory(fence.state_root(paths),'children'),cap['transaction_id'])
            with _child(cap):
                if fence.read_fence(paths) is not None: _fail()
                fence.publish_fence(paths,bridge._public_fence(expected,cap,record['service_startup']))
                bridge._advance_fence(paths,client,expected,'msi-starting')
            result={'result':'compound-prepared'}
        elif phase=='compound-old-returned':
            record=plan.read_plan(paths,cap)
            if record['phase']!='prepared': _fail()
            _native_products(cap,new_state=-1)
            provenance.validate_maintenance_recovery(paths,_old_request(paths,cap),'uninstall')
            installer_data_security.before_native(paths,data_request)
            # The owner policy grants this phase only after the actual old API0
            # and its script helpers have exited, before any successor script.
            plan.advance_plan(paths,cap,'old-script-returned',native_result=0)
        elif phase in {'compound-new-returned','compound-commit','compound-repair-returned','compound-repair-commit'}:
            record=plan.read_plan(paths,cap)
            required={'compound-new-returned':'old-script-returned','compound-commit':'new-script-returned',
                'compound-repair-returned':'prepared','compound-repair-commit':'repair-script-returned'}[phase]
            if record['phase']!=required: _fail()
            _verify_successor(paths,cap,expected)
            validate_native_intermediate(paths,cap,expected)
            plan.advance_plan(paths,cap,{'compound-new-returned':'new-script-returned','compound-commit':'committed',
                'compound-repair-returned':'repair-script-returned','compound-repair-commit':'repair-committed'}[phase],native_result=0)
        elif phase=='compound-retire':
            record=plan.read_plan(paths,cap)
            if record['phase'] not in {'committed','repair-committed'}: _fail()
            _verify_successor(paths,cap,expected)
            old_request=_old_request(paths,cap)
            old_expected=msi_inventory.read_expected_package(old_request['package_path'],old_request['release'])
            msi_inventory.verify_replaced_product(old_expected.package,expected.package,paths.install_root)
            if not cap['recovery']:provenance.validate_maintenance_recovery(paths,old_request,'uninstall')
            archived=plan._root(paths,cap)/'old-fence.json'
            original=fence.read_fence(paths)
            if original is None:
                source=archived
                if cap['recovery'] and not source.exists():
                    link=record['recovery']
                    candidates=[fence.state_root(paths)/'upgrades'/link[key]/'old-fence.json'
                        for key in ('predecessor_upgrade_id','original_upgrade_id')]
                    source=next((path for path in candidates if path.exists()),source)
                original=plan._read(source,secret=True)
                fence.validate_fence(original)
            old=_old_capability(paths,cap)
            wanted=bridge._public_fence(old_expected,old)
            if (original['phase']!='msi-executing' or original['startup_restored'] is not False
                or original['service_startup']!=record['service_startup']
                or any(original[key]!=wanted[key] for key in ('transaction_id','package','operation','selected','previous','service_states'))):
                _fail()
            if archived.exists() and plan._read(archived,secret=True)!=original: _fail()
            durable_state.write_json_atomic(archived,original,trusted_root=archived.parent,max_bytes=32768,
                protect=lambda target:fence.protect_state(target,secret=True))
            if cap['recovery']:provenance.retire_replaced_maintenance_authority(paths,old_request,request)
            else:provenance.retire_maintenance_authority(paths,old_request,'uninstall')
            # Never publish the immutable old helper's incompatible uninstall
            # finish receipt. Its actual native fence remains in the parent archive.
            durable_state.durable_unlink(fence.fence_path(paths),trusted_root=fence.state_root(paths),missing_ok=True)
            plan.advance_plan(paths,cap,'retired')
        elif phase in {'reconcile','finish'}:
            record=plan.read_plan(paths,cap)
            if record['phase']!=('retired' if phase=='reconcile' else 'reconciled'): _fail()
            _verify_successor(paths,cap,expected)
            if phase=='reconcile':validate_native_intermediate(paths,cap,expected)
            with _child(cap):
                result=bridge._execute_authorized_phase(client,paths,complete=False)
            if phase=='reconcile':plan.advance_plan(paths,cap,'reconciled')
        elif phase=='compound-complete':
            record=plan.read_plan(paths,cap)
            if record['phase']!='reconciled' or fence.read_fence(paths) is not None: _fail()
            with _child(cap):
                if fence.read_fence(paths) is not None: _fail()
            receipt_path=bridge.completion_root(paths,cap)/'completed.json'
            completed=plan._read(receipt_path)
            fence.validate_fence(completed)
            wanted=bridge._public_fence(expected,cap)
            if (completed['phase']!='complete' or completed['startup_restored'] is not True
                or any(completed[key]!=wanted[key] for key in ('transaction_id','package','operation','selected','previous','service_states'))):
                _fail()
            _verify_successor(paths,cap,expected)
            provenance.inspect_installed_core(paths,resulting_foundation=expected.package.version)
            result={'result':'compound-ready','marker':plan.ready_receipt(paths,cap)}
        else:
            raise ValueError('OWNER_AUTH_FAILED')
    client.request('complete',result)
    return result
