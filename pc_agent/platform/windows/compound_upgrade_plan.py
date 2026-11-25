"""Exact durable authority for an authenticated two-package foundation upgrade.

Package/session bindings and the original selected state are never re-baselined.
Native-result transitions are called only by owner-authorized bridge phases;
the owner policy separately proves actual API completion and delayed callbacks.
No credential content, credential digest or arbitrary path is accepted here.
"""
from copy import deepcopy
from hashlib import sha256
from itertools import islice
import os
import re
import stat
import uuid

from endpoint_contracts.runtime_payload import PayloadConflict, read_json, version_tuple
from . import durable_state, installer_fence

PHASES = ('prepared', 'old-script-returned', 'new-script-returned',
          'committed', 'retired', 'reconciled', 'ready')
REPAIR_PHASES = ('prepared','repair-script-returned','repair-committed','retired','reconciled','ready')
_HASH = re.compile(r'[0-9a-f]{64}')
_SOURCE = re.compile(r'[0-9a-f]{40}')
_BINDING = {'transaction_id', 'session_id', 'package', 'helper_sha256'}
_FIELDS = {'schema_version', 'upgrade_id', 'old', 'new', 'owner', 'selected',
           'previous', 'service_startup', 'browser_startup', 'phase', 'sequence'}
_BARRIER_FIELDS = {'schema_version', 'upgrade_id', 'new_transaction_id',
                   'old_package_sha256', 'new_package_sha256'}
_MAX_PLAN = 32768


def _failed():
    raise ValueError('PROVENANCE_CONFLICT')


def _uuid(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            _failed()
    except (ValueError, TypeError, AttributeError):
        _failed()


def _hash(value):
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        _failed()


def _release(value):
    from .msi_inventory import guid
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'version',
        'source_revision', 'package_sha256', 'product_code', 'initial_runtime_tree_sha256'}
        or value['schema_version'] != 'endpoint_windows_release_v1'
        or not isinstance(value['source_revision'], str) or not _SOURCE.fullmatch(value['source_revision'])):
        _failed()
    version_tuple(value['version'])
    if guid(value['product_code']) != value['product_code']:
        _failed()
    _hash(value['package_sha256']); _hash(value['initial_runtime_tree_sha256'])


def _child(value):
    if not isinstance(value, dict) or set(value) != _BINDING:
        _failed()
    _uuid(value['transaction_id']); _uuid(value['session_id'])
    _hash(value['helper_sha256']); _release(value['package'])


def _owner(value):
    if (not isinstance(value, dict) or set(value) != {'pid', 'created', 'hash', 'sid', 'elevated'}
        or type(value['pid']) is not int or value['pid'] <= 0
        or type(value['created']) is not int or value['created'] <= 0
        or value['elevated'] is not True or not isinstance(value['sid'], str)
        or not re.fullmatch(r'S-1-[0-9-]+', value['sid'])):
        _failed()
    _hash(value['hash'])


def _capability_binding(capability):
    compound = capability.get('compound')
    recovery=isinstance(compound,dict) and 'recovery' in compound
    prepared=isinstance(compound,dict) and 'prepared_old' in compound
    fields={'upgrade_id','old'}|({'recovery'} if recovery else set())|({'prepared_old'} if prepared else set())
    if (not isinstance(compound, dict) or set(compound) != fields
        or capability.get('operation') != 'install' or capability.get('recovery') is not recovery
        or capability.get('uninstall_finalization') is not False):
        _failed()
    if recovery:_recovery_link(compound['recovery'],compound['upgrade_id'])
    _uuid(compound['upgrade_id']); _child(compound['old'])
    new = {key: capability[key] for key in _BINDING}
    _child(new); _owner(capability['owner'])
    old = compound['old']
    if prepared:
        role=compound['prepared_old']
        if not isinstance(role,dict) or set(role)!={'source','capability_sha256','fence_sha256','maintenance_sha256'}:_failed()
        _child(role['source'])
        for key in ('capability_sha256','fence_sha256','maintenance_sha256'):_hash(role[key])
        if (any(role['source'][key]!=old[key] for key in _BINDING-{'session_id'})
            or role['source']['session_id'] in {old['session_id'],new['session_id']}):_failed()
    if (old['transaction_id'] == new['transaction_id'] or old['session_id'] == new['session_id']
        or old['helper_sha256'] == new['helper_sha256']
        or old['package']['package_sha256'] == new['package']['package_sha256']
        or old['package']['product_code'] == new['package']['product_code']
        or version_tuple(old['package']['version']) >= version_tuple(new['package']['version'])):
        _failed()
    for key in ('selected', 'previous'):
        if capability[key] is not None:
            _hash(capability[key])
    return deepcopy(old), deepcopy(new)


def _recovery_link(value,upgrade_id):
    if (not isinstance(value,dict) or set(value)!={'original_upgrade_id','original_plan_sha256',
        'predecessor_upgrade_id','predecessor_plan_sha256','mode'}
        or value['mode'] not in {'replace-foundation','repair-successor'}):_failed()
    for key in ('original_upgrade_id','predecessor_upgrade_id'):
        _uuid(value[key])
        if value[key]==upgrade_id:_failed()
    for key in ('original_plan_sha256','predecessor_plan_sha256'):_hash(value[key])


def _phases(record):
    return REPAIR_PHASES if record.get('recovery',{}).get('mode')=='repair-successor' else PHASES


def make_recovery_plan(capability,original,original_bytes,original_capability):
    """Copy the first before-state; this new owner starts its own progress.

    Mode is an observation to choose native work, never proof of settlement.
    Publication and every read additionally bind the protected original bytes.
    """
    old,new=_capability_binding(capability)
    if 'recovery' not in capability['compound']:_failed()
    link=capability['compound']['recovery']
    if (not isinstance(original_bytes,bytes) or not 0<len(original_bytes)<=_MAX_PLAN
        or read_json(original_bytes,_MAX_PLAN)!=original
        or sha256(original_bytes).hexdigest()!=link['original_plan_sha256']):_failed()
    validate_bound_plan(original,original_capability)
    if original['schema_version']!=1:_failed()
    if (original['upgrade_id']!=link['original_upgrade_id'] or capability['owner']==original['owner']
        or capability['compound'].get('prepared_old')!=original.get('prepared_old')
        or new['session_id']==original['new']['session_id']
        or any(new[key]!=original['new'][key] for key in ('transaction_id','package','helper_sha256'))
        or any(old[key]!=original['old'][key] for key in ('transaction_id','package','helper_sha256'))
        or any(capability[key]!=original[key] for key in ('selected','previous'))):_failed()
    if link['mode']=='replace-foundation':
        if old['session_id']==original['old']['session_id']:_failed()
    elif old['session_id']!=original['old']['session_id']:_failed()
    result={**deepcopy(original),'schema_version':2,'upgrade_id':capability['compound']['upgrade_id'],
        'old':old,'new':new,'owner':deepcopy(capability['owner']),'phase':'prepared','sequence':0,'recovery':deepcopy(link)}
    validate_bound_plan(result,capability)
    return result


def make_plan(capability, old_capability, old_fence, *, browser_startup=None,prepared_source=None):
    old, new = _capability_binding(capability)
    prepared='prepared_old' in capability['compound']
    if prepared:
        _validate_prepared_source(capability,prepared_source)
    if (old_capability.get('operation') != 'uninstall'
        or old_capability.get('recovery') is not prepared
        or old_capability.get('uninstall_finalization') is not False
        or {key: old_capability.get(key) for key in _BINDING} != old
        or old_capability.get('owner') != capability['owner']
        or old_fence.get('transaction_id') != old['transaction_id']
        or old_fence.get('operation') != 'uninstall' or old_fence.get('startup_restored') is not False
        or any(old_fence.get(key) != capability[key] for key in ('selected', 'previous'))
        or any(old_fence.get('package', {}).get(key) != old['package'][release_key]
               for key, release_key in (('sha256', 'package_sha256'), ('product_code', 'product_code'),
                   ('version', 'version'), ('source_revision', 'source_revision')))):
        _failed()
    record = {'schema_version': 1, 'upgrade_id': capability['compound']['upgrade_id'],
        'old': old, 'new': new, 'owner': deepcopy(capability['owner']),
        'selected': capability['selected'], 'previous': capability['previous'],
        'service_startup': deepcopy(old_fence['service_startup']), 'browser_startup':deepcopy(browser_startup),
        'phase': 'prepared', 'sequence': 0}
    if prepared:record['prepared_old']=deepcopy(capability['compound']['prepared_old'])
    validate_bound_plan(record, capability)
    return record


def validate_bound_plan(record, capability):
    old, new = _capability_binding(capability)
    recovery='recovery' in capability['compound']
    fields=_FIELDS|({'recovery'} if recovery else set())|({'prepared_old'} if 'prepared_old' in capability['compound'] else set())
    if (not isinstance(record, dict) or set(record) != fields
        or type(record['schema_version']) is not int or record['schema_version'] != (2 if recovery else 1)
        or record['upgrade_id'] != capability['compound']['upgrade_id']
        or record['old'] != old or record['new'] != new or record['owner'] != capability['owner']
        or any(record[key] != capability[key] for key in ('selected', 'previous'))
        or record['phase'] not in _phases(record) or type(record['sequence']) is not int
        or record['sequence'] != _phases(record).index(record['phase'])
        or (recovery and record['recovery']!=capability['compound']['recovery'])):
        _failed()
    if record.get('prepared_old')!=capability['compound'].get('prepared_old'):_failed()
    startup = record['service_startup']
    if not isinstance(startup, dict) or set(startup) != {'EndpointAgent', 'EndpointAgentUpdater'}:
        _failed()
    for value in startup.values():
        if (not isinstance(value, dict) or set(value) != {'start_type', 'delayed_auto'}
            or type(value['start_type']) is not int or value['start_type'] not in {2, 3, 4}
            or type(value['delayed_auto']) is not bool):
            _failed()
    browser=record['browser_startup']
    if browser is not None and (not isinstance(browser,dict) or set(browser)!={'start_type','delayed_auto'}
        or type(browser['start_type']) is not int or browser['start_type'] not in {2,3,4}
        or type(browser['delayed_auto']) is not bool):
        _failed()


def next_phase(record, capability, phase, *, native_result=None):
    validate_bound_plan(record, capability)
    index = record['sequence'] + 1
    phases=_phases(record)
    if index >= len(phases) or phases[index] != phase:
        _failed()
    if phase in {'old-script-returned', 'new-script-returned', 'committed','repair-script-returned','repair-committed'}:
        if type(native_result) is not int or native_result != 0:
            _failed()
    elif native_result is not None:
        _failed()
    result = deepcopy(record)
    result['phase'], result['sequence'] = phase, index
    return result


def _root(paths, capability):
    _capability_binding(capability)
    return installer_fence.state_root(paths)/'upgrades'/capability['compound']['upgrade_id']


def _read(path, *, secret=False, maximum=_MAX_PLAN):
    return read_json(_read_bytes(path,secret=secret,maximum=maximum),maximum)


def _read_bytes(path, *, secret=False, maximum=_MAX_PLAN):
    installer_fence.assert_state_security(path, secret=secret)
    details = path.lstat()
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1 or not 0 < details.st_size <= maximum:
        _failed()
    with path.open('rb') as stream:
        return stream.read(maximum + 1)


def _read_recovery_plan(root):
    """Preserve the original before-state across a torn phase replacement."""
    raw = _read_bytes(root / 'plan.json', secret=True)
    try:
        return read_json(raw, _MAX_PLAN), raw
    except PayloadConflict as damaged:
        # Only an unreadable payload can select the prepared copy. The same
        # ACL, bound capability, pointer and native recovery checks still apply.
        try:
            raw = _read_bytes(root / 'prepared-plan.json', secret=True)
        except FileNotFoundError:
            raise damaged
        prepared = read_json(raw, _MAX_PLAN)
        if prepared.get('phase') != 'prepared' or prepared.get('sequence') != 0:
            _failed()
        return prepared, raw


def _validate_prepared_source(capability,source):
    role=capability['compound']['prepared_old']
    if (not isinstance(source,dict) or 'compound' in source or 'recovery_parent' in source
        or source.get('operation')!='uninstall' or source.get('recovery') is not False
        or source.get('uninstall_finalization') is not False or source.get('owner')!=capability['owner']
        or {key:source.get(key) for key in _BINDING}!=role['source']
        or any(source.get(key)!=capability[key] for key in ('selected','previous'))):_failed()


def read_prepared_source(paths,capability):
    """Read exact archived preparation, never infer a fresh role from absence."""
    _capability_binding(capability)
    role=capability['compound']['prepared_old']
    authority=capability
    if capability['recovery']:
        _original,_raw,authority=read_recovery_original(paths,capability)
    root=installer_fence.state_root(paths)
    from .installer_transaction_bridge import _read_capability
    source=_read_capability(paths,role['source']['session_id'])
    _validate_prepared_source(authority,source)
    source_bytes=_read_bytes(root/'capabilities'/f"{source['session_id']}.json",secret=True,maximum=16384)
    if read_json(source_bytes,16384)!=source or sha256(source_bytes).hexdigest()!=role['capability_sha256']:_failed()
    archive=root/'prepared-old'/source['session_id']
    installer_fence.assert_state_security(archive,secret=True)
    saved={}
    for name in ('fence','maintenance'):
        raw=_read_bytes(archive/f'{name}.json',secret=True,maximum=16384)
        if sha256(raw).hexdigest()!=role[name+'_sha256']:_failed()
        saved[name]=read_json(raw,16384)
    before=saved['fence']
    if (before.get('phase')!='msi-starting' or before.get('transaction_id')!=source['transaction_id']
        or before.get('operation')!='uninstall' or before.get('startup_restored') is not False
        or any(before.get(key)!=source[key] for key in ('selected','previous'))):_failed()
    maintenance=saved['maintenance']
    if (maintenance.get('transaction_id')!=source['transaction_id'] or maintenance.get('operation')!='uninstall'
        or maintenance.get('release')!=source['package']):_failed()
    return source,before,saved['maintenance']


def read_plan(paths, capability):
    root = _root(paths, capability)
    installer_fence.assert_state_security(root, secret=True)
    record = _read(root/'plan.json', secret=True)
    _validate_stored_plan(paths, capability, record)
    if _read(installer_fence.state_root(paths)/'upgrade.json', maximum=4096) != _barrier(record):
        _failed()
    return record


def _validate_stored_plan(paths, capability, record):
    validate_bound_plan(record, capability)
    if 'prepared_old' in record:read_prepared_source(paths,capability)
    if 'recovery' in record:
        original,raw,original_cap=read_recovery_original(paths,capability)
        prepared=make_recovery_plan(capability,original,raw,original_cap)
        if any(record[key]!=prepared[key] for key in _FIELDS-{'phase','sequence'}):_failed()


def read_recovery_original(paths,capability):
    _capability_binding(capability)
    link=capability['compound']['recovery']
    root=installer_fence.state_root(paths)/'upgrades'/link['original_upgrade_id']
    installer_fence.assert_state_security(root,secret=True)
    original,raw=_read_recovery_plan(root)
    if sha256(raw).hexdigest()!=link['original_plan_sha256']:_failed()
    if not isinstance(original,dict) or original.get('schema_version')!=1:_failed()
    from .installer_transaction_bridge import _read_capability
    original_cap=_read_capability(paths,original['new']['session_id'])
    make_recovery_plan(capability,original,raw,original_cap)
    _read_recovery_predecessor(paths,capability,original)
    return original,raw,original_cap


def _read_recovery_predecessor(paths,capability,original):
    """Every attempt read keeps its immediate declared dependency exact."""
    link=capability['compound']['recovery']
    root=installer_fence.state_root(paths)/'upgrades'/link['predecessor_upgrade_id']
    installer_fence.assert_state_security(root,secret=True)
    previous,raw=_read_recovery_plan(root)
    if sha256(raw).hexdigest()!=link['predecessor_plan_sha256']:_failed()
    from .installer_transaction_bridge import _read_capability
    previous_cap=_read_capability(paths,previous['new']['session_id'])
    validate_bound_plan(previous,previous_cap)
    if (previous['upgrade_id']!=link['predecessor_upgrade_id'] or previous['owner']==capability['owner']
        or previous.get('prepared_old')!=original.get('prepared_old')
        or previous['new']['session_id']==capability['session_id']
        or any(previous[key]!=original[key] for key in ('selected','previous','service_startup','browser_startup'))
        or (previous['schema_version']==2 and any(previous['recovery'][key]!=link[key]
            for key in ('original_upgrade_id','original_plan_sha256')))):_failed()
    for role in ('old','new'):
        if any(previous[role][key]!=original[role][key] for key in ('transaction_id','package','helper_sha256')):_failed()
    return previous


def _recovery_committed_marker(paths,barrier):
    """Invalid terminal content is unresolved; unsafe namespace is rejected."""
    history=installer_fence.state_root(paths)/'upgrade-history'/barrier['upgrade_id']
    marker=history/'complete.json'
    try:marker.lstat()
    except FileNotFoundError:return None
    installer_fence.assert_state_security(history)
    for name in ('barrier.json','ready.json','complete.json'):
        path=history/name;installer_fence.assert_state_security(path)
        details=path.lstat()
        if not stat.S_ISREG(details.st_mode) or details.st_nlink!=1 or not 0<=details.st_size<=4096:_failed()
    # The archived barrier is authority, not expendable terminal content.
    if _read(history/'barrier.json',maximum=4096)!=barrier:_failed()
    try:return committed_marker(paths,barrier=barrier)
    except ValueError:return None


def _unconfirmed_fence(fence, binding, operation, record, *, starting_is_ambiguous):
    if fence is None or fence['transaction_id'] != binding['transaction_id']:
        return False
    package = binding['package']
    if (fence['operation'] != operation or fence['selected'] != record['selected']
            or fence['previous'] != record['previous']
            or any(fence['package'][key] != package[name] for key, name in (
                ('sha256','package_sha256'), ('product_code','product_code'),
                ('version','version'), ('source_revision','source_revision')))):
        _failed()
    return (fence['phase'] in {'msi-executing', 'msi-returned', 'reconciling', 'complete'}
            or (starting_is_ambiguous and fence['phase'] == 'msi-starting'))


def _unconfirmed_msi(paths, record):
    """Either leg can enter MSI before the compound outcome is durable."""
    # Only the authenticated compound End transition proves that a returned
    # script committed. Product registration and either callback do not.
    if record['phase'] in {'committed', 'repair-committed', 'retired', 'reconciled', 'ready'}:
        return False
    if record['phase'] in {'old-script-returned', 'new-script-returned', 'repair-script-returned'}:
        return True
    from . import staged_recovery, staged_update_state
    staged = staged_update_state.read_staged_update(paths)
    staged_matches = staged is not None and staged.binding.operation_id == record['new']['transaction_id']
    if staged_matches:
        if (staged.binding.old_release != record['old']['package']
                or staged.binding.new_release != record['new']['package']):
            _failed()
        # A staged attempt is persisted before either MSI API is called.
        # Even an exit code or staged terminal phase is contradictory while
        # the authenticated compound End is missing.
        if (staged.phase not in {'preparing', 'prepared', 'switching'}
                or staged_recovery._native_attempt(paths, staged) is not None):
            return True
    # Historic standalone compounds have no pre-API attempt receipt. Their
    # starting fence cannot distinguish before entry from before the callback.
    old = installer_fence.read_fence(paths)
    if _unconfirmed_fence(old, record['old'], 'uninstall', record,
                          starting_is_ambiguous=not staged_matches):
        return True
    target = record['new']
    attempt_id = record['upgrade_id'] if record['schema_version'] == 2 else None
    with installer_fence.child_fence(target['transaction_id'], attempt_id=attempt_id):
        child = installer_fence.read_fence(paths)
    if child is not None and child['transaction_id'] != target['transaction_id']:
        _failed()
    return _unconfirmed_fence(child, target, 'install', record,
                             starting_is_ambiguous=not staged_matches)


def assert_recovery_msi_outcome(paths, capability, original):
    previous = _read_recovery_predecessor(paths, capability, original)
    if _unconfirmed_msi(paths, original) or (
            previous['upgrade_id'] != original['upgrade_id'] and _unconfirmed_msi(paths, previous)):
        raise ValueError('MSI_OUTCOME_UNCONFIRMED')
    return previous


def inspect_recovery_authority(paths,release,*,helper_sha256=None):
    """Read-only discovery of an exact surviving parent, never settlement."""
    pointer=installer_fence.state_root(paths)/'upgrade.json'
    try:pointer.lstat()
    except FileNotFoundError:
        if has_active_upgrade(paths):_failed()
        return None
    barrier=_read(pointer,maximum=4096)
    _validate_barrier(barrier)
    if _recovery_committed_marker(paths,barrier) is not None:return None
    root=installer_fence.state_root(paths)/'upgrades'/barrier['upgrade_id']
    installer_fence.assert_state_security(root,secret=True)
    record,raw=_read_recovery_plan(root)
    from .installer_transaction_bridge import _read_capability
    current_cap=_read_capability(paths,record['new']['session_id'])
    validate_bound_plan(record,current_cap)
    if (_barrier(record)!=barrier or record['new']['package']!=release
        or (helper_sha256 is not None and record['new']['helper_sha256']!=helper_sha256)):_failed()
    if record['schema_version']==2:
        original,original_raw,original_cap=read_recovery_original(paths,current_cap)
        expected=make_recovery_plan(current_cap,original,original_raw,original_cap)
        if any(record[key]!=expected[key] for key in _FIELDS-{'phase','sequence'}):_failed()
    else:original,original_raw,original_cap=record,raw,current_cap
    result={'parent_upgrade_id':record['upgrade_id'],'transaction_id':original['new']['transaction_id'],
        'selected':original['selected'],'previous':original['previous'],'service_states':original_cap['service_states'],
        'old':deepcopy(original['old']),'original_upgrade_id':original['upgrade_id'],
        'original_plan_sha256':sha256(original_raw).hexdigest(),'predecessor_plan_sha256':sha256(raw).hexdigest()}
    if _unconfirmed_msi(paths, original) or (record is not original and _unconfirmed_msi(paths, record)):
        result['msi_outcome_unconfirmed'] = True
    if 'prepared_old' in original:
        read_prepared_source(paths,current_cap)
        result['prepared_old']=deepcopy(original['prepared_old'])
    return result


def publish_recovery_plan(paths,capability,record):
    """Select a new attempt without changing original or predecessor evidence."""
    from .installation_provenance import _archive_directory
    original,raw,original_cap=read_recovery_original(paths,capability)
    if record!=make_recovery_plan(capability,original,raw,original_cap):_failed()
    previous=assert_recovery_msi_outcome(paths,capability,original)
    barrier=installer_fence.state_root(paths)/'upgrade.json'
    if _read(barrier,maximum=4096)!=_barrier(previous):_failed()
    # A valid terminal predecessor is already complete. Invalid/torn publication
    # remains untouched; only genuine serialized recovery can establish a new
    # terminal attempt, without rewriting the historical leaf.
    committed=_recovery_committed_marker(paths,_barrier(previous))
    if committed is not None:_failed()
    root=_root(paths,capability)
    if root.exists():installer_fence.assert_state_security(root,secret=True)
    else:
        _archive_directory(_archive_directory(root.parent.parent,root.parent.name),root.name)
        installer_fence.protect_state(root,secret=True)
    path=root/'plan.json'
    if path.exists() and _read(path,secret=True)!=record:_failed()
    _immutable_json(root/'prepared-plan.json',record,secret=True,maximum=_MAX_PLAN)
    durable_state.write_json_atomic(path,record,trusted_root=root,max_bytes=_MAX_PLAN,
        protect=lambda target:installer_fence.protect_state(target,secret=True))
    _immutable_json(_history(paths,record['upgrade_id'])/'barrier.json',_barrier(record))
    durable_state.write_json_atomic(barrier,_barrier(record),trusted_root=barrier.parent,max_bytes=4096,
        protect=installer_fence.protect_state)


def _barrier(record):
    return {'schema_version': 1, 'upgrade_id': record['upgrade_id'],
            'new_transaction_id': record['new']['transaction_id'],
            'old_package_sha256': record['old']['package']['package_sha256'],
            'new_package_sha256': record['new']['package']['package_sha256']}


def publish_plan(paths, capability, record):
    from .installation_provenance import _archive_directory
    validate_bound_plan(record, capability)
    root = _root(paths, capability)
    if root.exists():
        installer_fence.assert_state_security(root, secret=True)
    else:
        _archive_directory(_archive_directory(root.parent.parent, root.parent.name), root.name)
        installer_fence.protect_state(root, secret=True)
    path = root/'plan.json'
    if path.exists() and _read(path, secret=True) != record:
        _failed()
    barrier_path = installer_fence.state_root(paths)/'upgrade.json'
    previous=None
    if barrier_path.exists():
        active=_read(barrier_path,maximum=4096)
        if active!=_barrier(record):
            previous=committed_marker(paths)
            if previous is None:_failed()
            if (previous['new_package_sha256']!=record['old']['package']['package_sha256']
                or previous['successor_product_code']!=record['old']['package']['product_code']
                or previous['source_revision']!=record['old']['package']['source_revision']):
                validate_standalone_predecessor(paths,record['old']['package'],previous)
    history=_history(paths,record['upgrade_id'])
    _immutable_json(history/'barrier.json',_barrier(record))
    if previous is not None:
        _immutable_json(root/'predecessor.json',previous,secret=True)
    _immutable_json(root/'prepared-plan.json',record,secret=True,maximum=_MAX_PLAN)
    durable_state.write_json_atomic(path, record, trusted_root=root, max_bytes=_MAX_PLAN,
        protect=lambda target: installer_fence.protect_state(target, secret=True))
    durable_state.write_json_atomic(barrier_path, _barrier(record), trusted_root=barrier_path.parent,
        max_bytes=4096, protect=installer_fence.protect_state)


def advance_plan(paths, capability, phase, *, native_result=None):
    record = next_phase(read_plan(paths, capability), capability, phase, native_result=native_result)
    root = _root(paths, capability)
    durable_state.write_json_atomic(root/'plan.json', record, trusted_root=root, max_bytes=_MAX_PLAN,
        protect=lambda target: installer_fence.protect_state(target, secret=True))
    return record


def has_active_upgrade(paths):
    path = installer_fence.state_root(paths)/'upgrade.json'
    try:
        path.lstat()
    except FileNotFoundError:
        # A missing selector cannot erase a known compound lifecycle. Normal
        # uninstall leaves this small public history intact; clean reinstall
        # and later OTA do not rewrite its terminal authority.
        try:(installer_fence.state_root(paths)/'upgrade-history').lstat()
        except FileNotFoundError:return False
        return True
    value = _read(path, maximum=4096)
    _validate_barrier(value)
    return committed_marker(paths,barrier=value) is None


def _validate_barrier(value):
    if (not isinstance(value, dict) or set(value) != _BARRIER_FIELDS
        or type(value['schema_version']) is not int or value['schema_version'] != 1):
        _failed()
    _uuid(value['upgrade_id']); _uuid(value['new_transaction_id'])
    _hash(value['old_package_sha256']); _hash(value['new_package_sha256'])
    if value['old_package_sha256'] == value['new_package_sha256']:
        _failed()


def _history(paths,upgrade_id):
    from .installation_provenance import _archive_directory
    _uuid(upgrade_id)
    return _archive_directory(_archive_directory(installer_fence.state_root(paths),'upgrade-history'),upgrade_id)


def _immutable_json(path,value,*,secret=False,maximum=4096):
    if path.exists():
        if _read(path,secret=secret,maximum=maximum)!=value:_failed()
        return
    durable_state.write_json_atomic(path,value,trusted_root=path.parent,max_bytes=maximum,
        protect=lambda target:installer_fence.protect_state(target,secret=secret))


def ready_receipt(paths,capability):
    """Public readiness is durable before ACK; it never opens the launch gate."""
    record=read_plan(paths,capability)
    if record['phase']!='reconciled':_failed()
    value={**_barrier(record),'successor_product_code':record['new']['package']['product_code'],
        'source_revision':record['new']['package']['source_revision'],'phase':'ready'}
    history=_history(paths,record['upgrade_id'])
    _immutable_json(history/'ready.json',value)
    raw=_read_bytes(history/'ready.json',maximum=4096)
    advance_plan(paths,capability,'ready')
    return {**{key:item for key,item in value.items() if key!='phase'},'ready_sha256':sha256(raw).hexdigest()}


def committed_marker(paths,*,barrier=None):
    """Read only public historical facts, never current selectors or secrets."""
    if barrier is None:
        barrier=_read(installer_fence.state_root(paths)/'upgrade.json',maximum=4096)
    _validate_barrier(barrier)
    history=installer_fence.state_root(paths)/'upgrade-history'/barrier['upgrade_id']
    path=history/'complete.json'
    try:path.lstat()
    except FileNotFoundError:return None
    installer_fence.assert_state_security(history)
    if _read(history/'barrier.json',maximum=4096)!=barrier:_failed()
    raw=_read_bytes(history/'ready.json',maximum=4096)
    ready=read_json(raw,4096)
    if (not isinstance(ready,dict) or set(ready)!=_BARRIER_FIELDS|{'successor_product_code','source_revision','phase'}
        or ready['phase']!='ready' or any(ready[key]!=barrier[key] for key in _BARRIER_FIELDS)
        or not isinstance(ready['source_revision'],str) or not _SOURCE.fullmatch(ready['source_revision'])):_failed()
    from .msi_inventory import guid
    if guid(ready['successor_product_code'])!=ready['successor_product_code']:_failed()
    expected={**{key:item for key,item in ready.items() if key!='phase'},'ready_sha256':sha256(raw).hexdigest()}
    if _read(path,maximum=4096)!=expected:_failed()
    return expected


def superseded_starting_child(paths, leaf):
    """Prove an unentered original child was replaced by a committed native recovery."""
    root = installer_fence.state_root(paths)
    relative = leaf.relative_to(root/'children').parts
    if len(relative) != 2 or relative[1] != 'transaction.json':
        return False
    transaction = relative[0]
    try:
        _uuid(transaction)
        child = installer_fence.validate_fence(_read(leaf, maximum=installer_fence.MAX_FENCE_BYTES))
        if (child['transaction_id'] != transaction or child['operation'] != 'install'
                or child['phase'] != 'msi-starting' or child['sequence'] != 1 or child['startup_restored']):
            return False
        attempts = root/'transactions'/transaction/'attempts'
        installer_fence.assert_state_security(attempts)
        with os.scandir(attempts) as entries:
            candidates = list(islice(entries, 513))
        if len(candidates) > 512:
            return False
        return any(entry.is_dir(follow_symlinks=False)
                   and _committed_child_replacement(paths, child, entry.name) for entry in candidates)
    except (OSError, ValueError):
        return False


def _committed_child_replacement(paths, child, attempt):
    from .installer_transaction_bridge import _read_capability, completion_root

    root = installer_fence.state_root(paths)
    try:
        _uuid(attempt)
        directory = root/'upgrades'/attempt
        installer_fence.assert_state_security(directory, secret=True)
        record = _read(directory/'plan.json', secret=True)
        if (record['schema_version'] != 2 or record['upgrade_id'] != attempt or record['phase'] != 'ready'
                or record['new']['transaction_id'] != child['transaction_id']):
            return False
        cap = _read_capability(paths, record['new']['session_id'])
        if cap['operation'] != 'install' or not cap['recovery']:
            return False
        _validate_stored_plan(paths, cap, record)
        marker = committed_marker(paths, barrier=_barrier(record))
        if (marker is None or marker['successor_product_code'] != cap['package']['product_code']
                or marker['source_revision'] != cap['package']['source_revision']):
            return False
        receipt = _read(completion_root(paths, cap)/'completed.json', maximum=installer_fence.MAX_FENCE_BYTES)
        _validate_completed(receipt, cap['package'], child['transaction_id'], 'install')
        return (receipt['service_states'] == cap['service_states']
                and receipt['service_startup'] == record['service_startup']
                and all(receipt[key] == record[key] for key in ('selected', 'previous'))
                and all(receipt[key] == child[key] for key in
                        ('package', 'selected', 'previous', 'service_states', 'service_startup')))
    except (OSError, ValueError, KeyError, TypeError):
        return False


def record_standalone_completion(paths,capability,completed):
    """Bind ordinary reinstall/uninstall to the retained compound history.

    Called by authenticated finish before its global fence is retired. This
    records an actual completed native lifecycle, never an idle observation.
    """
    if 'compound' in capability or capability['operation'] not in {'install','uninstall'}:return
    root=installer_fence.state_root(paths)
    if not (root/'upgrade.json').exists():
        if has_active_upgrade(paths):_failed()
        return
    previous=committed_marker(paths)
    if previous is None:_failed()
    _validate_completed(completed,capability['package'],capability['transaction_id'],capability['operation'])
    receipt=root/'transactions'/capability['transaction_id']/'completed.json'
    raw=_read_bytes(receipt,maximum=16384)
    if read_json(raw,16384)!=completed:_failed()
    value={'schema_version':1,'transaction_id':capability['transaction_id'],'operation':capability['operation'],
        'package':capability['package'],'previous_upgrade_id':previous['upgrade_id'],
        'previous_ready_sha256':previous['ready_sha256'],'receipt_sha256':sha256(raw).hexdigest()}
    durable_state.write_json_atomic(root/'standalone-lifecycle.json',value,trusted_root=root,max_bytes=4096,
        protect=installer_fence.protect_state)


def _validate_completed(value,package,transaction,operation):
    installer_fence.validate_fence(value)
    if (value['transaction_id']!=transaction or value['operation']!=operation or value['phase']!='complete'
        or value['startup_restored'] is not True or any(value['package'][key]!=package[release_key]
            for key,release_key in (('sha256','package_sha256'),('version','version'),('source_revision','source_revision'),('product_code','product_code')))):_failed()


def validate_standalone_predecessor(paths,package,previous):
    root=installer_fence.state_root(paths)
    value=_read(root/'standalone-lifecycle.json',maximum=4096)
    if (not isinstance(value,dict) or set(value)!={'schema_version','transaction_id','operation','package',
        'previous_upgrade_id','previous_ready_sha256','receipt_sha256'}
        or type(value['schema_version']) is not int or value['schema_version']!=1 or value['operation']!='install'
        or value['package']!=package or value['previous_upgrade_id']!=previous['upgrade_id']
        or value['previous_ready_sha256']!=previous['ready_sha256']):_failed()
    _uuid(value['transaction_id']);_hash(value['receipt_sha256'])
    raw=_read_bytes(root/'transactions'/value['transaction_id']/'completed.json',maximum=16384)
    if sha256(raw).hexdigest()!=value['receipt_sha256']:_failed()
    _validate_completed(read_json(raw,16384),package,value['transaction_id'],'install')
