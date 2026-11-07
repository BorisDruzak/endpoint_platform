"""Handoff only owned sensors in existing genuine graphical user managers."""
import os
from pathlib import Path
import re
import stat
import hashlib
import json

from tools.release.linux_native_verifier import run, VerificationError
from pc_agent.platform.linux.installation_lifecycle import InstallationPending


def session_uid(properties):
    if (properties.get('Active') != 'yes' or properties.get('Remote') != 'no'
        or properties.get('Class') != 'user' or properties.get('Type') not in ('x11', 'wayland')
        or properties.get('State') != 'active' or not re.fullmatch('[1-9][0-9]{0,9}', properties.get('User', ''))):
        return None
    uid = int(properties['User'])
    return uid if 0 < uid < 2**31 else None


def eligible_owned_unit(properties):
    return (properties.get('LoadState') == 'loaded'
        and properties.get('FragmentPath') == '/usr/lib/systemd/user/endpoint-user-sensor.service'
        and not properties.get('DropInPaths')
        and properties.get('UnitFileState') not in ('masked', 'masked-runtime')
        and (properties.get('ActiveState') == 'active' or properties.get('UnitFileState') in ('enabled','enabled-runtime')))


def session_ids():
    rows = run(['/usr/bin/loginctl', 'list-sessions', '--no-legend', '--no-pager']).decode().splitlines()
    return [row.split()[0] for row in rows[:128] if row.split() and re.fullmatch('[a-zA-Z0-9_-]{1,32}', row.split()[0])]


def properties(raw):
    return dict(row.split('=', 1) for row in raw.decode().splitlines() if '=' in row)


def read_session_environment(runtime, uid):
    environment = runtime/'endpoint-user-sensor.env'
    try:
        # Existence is optional; a symlink/bad mode/foreign owner is not absence.
        environment.lstat()
        fd = os.open(environment, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16384:
            raise InstallationPending('unsafe_sensor_environment')
        raw = os.read(fd, 16385)
        if not re.search(r'(?m)^(DISPLAY|WAYLAND_DISPLAY)="[^"\r\n]+"$', raw.decode('utf-8')):
            return None
        def identity(node):
            return (node.st_dev,node.st_ino,node.st_mode,node.st_uid,node.st_gid,
                node.st_size,node.st_nlink,node.st_mtime_ns,node.st_ctime_ns)
        try:
            current = environment.lstat()
        except FileNotFoundError:
            return None
        if identity(os.fstat(fd)) != identity(info) or identity(current) != identity(info):
            raise InstallationPending('sensor_environment_changed')
        return {'digest':hashlib.sha256(raw).hexdigest(), 'device':info.st_dev,
            'inode':info.st_ino,'mtime':info.st_mtime_ns,'ctime':info.st_ctime_ns}
    finally:
        os.close(fd)


def session_context(sid):
    import pwd
    try:
        session = properties(run(['/usr/bin/loginctl', 'show-session', sid, '--no-pager',
            '--property=Active,Remote,Class,Type,User,State,TimestampMonotonic,Leader']))
    except (VerificationError, OSError):
        if sid not in session_ids():
            return None
        raise
    uid = session_uid(session)
    if uid is None:
        return None
    try:
        account = pwd.getpwuid(uid)
        runtime = Path('/run/user')/str(uid)
        info = runtime.lstat()
    except (FileNotFoundError, KeyError):
        return None
    if runtime.resolve() != runtime or not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
        raise InstallationPending('unsafe_sensor_runtime')
    environment = read_session_environment(runtime, uid)
    if environment is None:
        return None
    # Directory identity/timestamps detect explicit unit configuration changes,
    # including enable/disable/mask edits while the owned service is stopped.
    configuration = []
    for base in (Path(account.pw_dir)/'.config/systemd', runtime/'systemd'):
        for suffix in ('user','user.control','user/graphical-session.target.wants'):
            path = base/suffix
            try:
                node = path.lstat()
                configuration.append([str(path),node.st_dev,node.st_ino,node.st_ctime_ns])
            except FileNotFoundError:
                configuration.append([str(path),None])
    prefix = ['/sbin/runuser', '-u', account.pw_name, '--', '/usr/bin/env', '-i',
        'PATH=/usr/bin:/bin', f'XDG_RUNTIME_DIR={runtime}',
        f'DBUS_SESSION_BUS_ADDRESS=unix:path={runtime}/bus', '/usr/bin/systemctl', '--user']
    return {'sid':sid,'uid':uid,'session':session,'environment':environment,
        'runtime':[info.st_dev,info.st_ino], 'configuration':configuration,
        'boot':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'prefix':prefix}


def unit_properties(context):
    return properties(run([*context['prefix'], 'show', 'endpoint-user-sensor.service',
        '--property=LoadState,UnitFileState,FragmentPath,ActiveState,DropInPaths,InactiveEnterTimestampMonotonic,ActiveEnterTimestampMonotonic']))


def retained_unit_matches(retained, props, store):
    if retained['after'] == props:
        return True
    # An inactive unreferenced unit can be garbage-collected across RPM removal.
    # Accept only a freshly loaded zero-timestamp unit after our confirmed erase;
    # a new user start/stop has nonzero timestamps and never matches this case.
    operation_id = retained.get('operation_id')
    receipt = store.json('receipt-' + operation_id + '.json', missing=True) if store and operation_id else None
    if not (receipt and receipt.get('action') == 'remove' and type(receipt.get('exit_code')) is int
        and receipt['exit_code'] == 0 and receipt.get('settled')
        and (receipt.get('event') or {}).get('action') == 'removed'):
        return False
    timestamps = ('InactiveEnterTimestampMonotonic','ActiveEnterTimestampMonotonic')
    return (all(props.get(key, '0') == '0' for key in timestamps)
        and {k:v for k,v in props.items() if k not in timestamps}
            == {k:v for k,v in retained['after'].items() if k not in timestamps})


def preparation_sensor_receipts(store):
    operation = (store.json('state.json', missing=True) or {}).get('operation') or {}
    return {uid:receipt for uid,receipt in (store.json('sensor-handoff.json', missing=True) or {}).items()
        if receipt.get('operation_id') == operation.get('id') and receipt.get('phase') in ('stop_pending','stopped')}


def assert_preparation_handoffs(store):
    # Recovery cannot silently skip an owned stop whose outcome is unresolved.
    for receipt in preparation_sensor_receipts(store).values():
        context = session_context(receipt['context']['sid'])
        if context != receipt['context']:
            raise InstallationPending('preparation_sensor_context_pending')
        expected = receipt['before'] if receipt['phase'] == 'stop_pending' else receipt['after']
        if unit_properties(context) != expected:
            raise InstallationPending('preparation_sensor_stop_outcome_pending')


def handoff_active_sensors(*, stop=False, store=None, retained_only=False):
    receipts = (store.json('sensor-handoff.json', missing=True) or {}) if store else {}
    seen, results = set(), []
    def save():
        if store:
            store.write('sensor-handoff.json', json.dumps(receipts).encode())
    if retained_only:
        assert_preparation_handoffs(store)
        sessions = list(dict.fromkeys(x['context']['sid'] for x in preparation_sensor_receipts(store).values()))
    else:
        sessions = session_ids()
    for sid in sessions:
        context = session_context(sid)
        if context is None:
            results.append({'session':sid,'status':'session_prerequisite_absent'})
            continue
        uid = str(context['uid'])
        if uid in seen:
            continue
        seen.add(uid)
        prefix = context['prefix']
        try:
            props = unit_properties(context)
        except (VerificationError, OSError):
            if session_context(sid) is None:
                results.append({'session':sid,'status':'session_vanished'})
                continue
            raise
        retained = receipts.get(uid)
        if retained_only and retained and retained['phase'] == 'stop_pending':
            if context != retained['context'] or props != retained['before']:
                raise InstallationPending('preparation_sensor_stop_outcome_pending')
            # Exact original state proves no stop took effect; no restart needed.
            retained['phase'] = 'not_stopped'
            save()
            results.append({'session':sid,'uid':int(uid),'status':'unchanged_before_stop'})
            continue
        resume = bool(retained and retained['phase'] == 'stopped' and retained['context'] == context
            and retained_unit_matches(retained, props, store) and retained['before']['ActiveState'] == 'active'
            and props['ActiveState'] == 'inactive')
        eligible = eligible_owned_unit(props)
        if stop:
            eligible = eligible and props['ActiveState'] == 'active'
        elif retained_only:
            eligible = False
        if not resume and not eligible:
            results.append({'session':sid,'status':'unit_ineligible_or_changed'})
            continue
        if session_context(sid) != context:
            results.append({'session':sid,'status':'session_changed'})
            continue
        if stop:
            if store is None:
                raise InstallationPending('durable_sensor_stop_receipt_required')
            operation = (store.json('state.json', missing=True) or {}).get('operation') or {}
            receipts[uid] = {'context':context,'before':props,'phase':'stop_pending','after':None,
                'operation_id':operation.get('id')}
            save()
        try:
            run([*prefix, 'daemon-reload'])
            # Reload must not introduce a user override or consume changed state.
            if unit_properties(context) != props:
                raise InstallationPending('sensor_unit_changed_during_handoff')
            run([*prefix, 'stop' if stop else 'restart', 'endpoint-user-sensor.service'], timeout=25)
        except (VerificationError, OSError):
            if session_context(sid) is None:
                results.append({'session':sid,'status':'session_vanished'})
                continue
            raise
        if stop:
            try:
                after = unit_properties(context)
            except (VerificationError, OSError):
                if session_context(sid) is None:
                    results.append({'session':sid,'status':'session_vanished'})
                    continue
                raise
            if after.get('ActiveState') != 'inactive':
                raise InstallationPending('sensor_stop_not_confirmed')
            receipts[uid].update(phase='stopped',after=after)
            save()
        elif resume:
            if retained_only:
                restored = unit_properties(context)
                stable = ('LoadState','FragmentPath','DropInPaths','UnitFileState','ActiveState')
                if session_context(sid) != context or any(restored.get(key) != retained['before'].get(key) for key in stable):
                    raise InstallationPending('preparation_sensor_restoration_pending')
            receipts[uid]['phase'] = 'consumed'
            save()
        results.append({'session':sid,'uid':int(uid),
            'status':'stopped_owned' if stop else 'resumed_owned_stop' if resume else 'restarted_active_or_enabled'})
    if retained_only and preparation_sensor_receipts(store):
        raise InstallationPending('preparation_sensor_restoration_pending')
    return results
