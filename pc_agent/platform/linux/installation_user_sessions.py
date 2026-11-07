"""Handoff only owned sensors in existing genuine graphical user managers."""
import os
from pathlib import Path
import re
import stat

from tools.release.linux_native_verifier import run


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


def handoff_active_sensors(*, stop=False):
    import pwd
    sessions = run(['/usr/bin/loginctl', 'list-sessions', '--no-legend', '--no-pager']).decode().splitlines()
    seen, restarted = set(), []
    for line in sessions[:128]:
        sid = line.split()[0]
        if not re.fullmatch('[a-zA-Z0-9_-]{1,32}', sid):
            continue
        raw = run(['/usr/bin/loginctl', 'show-session', sid, '--no-pager',
            '--property=Active,Remote,Class,Type,User,State']).decode()
        uid = session_uid(dict(row.split('=', 1) for row in raw.splitlines() if '=' in row))
        if uid is None or uid in seen:
            continue
        seen.add(uid)
        account = pwd.getpwuid(uid)
        runtime = Path('/run/user')/str(uid)
        info = runtime.lstat()
        if runtime.resolve() != runtime or not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
            continue
        environment = runtime/'endpoint-user-sensor.env'
        fd = os.open(environment, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16384:
                continue
            raw = os.read(fd, 16385).decode('utf-8')
        finally:
            os.close(fd)
        # Do not evaluate user content. The existing user's manager reads its own
        # environment file; every command below runs as that exact existing UID.
        if not re.search(r'(?m)^(DISPLAY|WAYLAND_DISPLAY)="[^"\r\n]+"$', raw):
            continue
        prefix = ['/sbin/runuser', '-u', account.pw_name, '--', '/usr/bin/env', '-i',
            'PATH=/usr/bin:/bin', f'XDG_RUNTIME_DIR={runtime}',
            f'DBUS_SESSION_BUS_ADDRESS=unix:path={runtime}/bus', '/usr/bin/systemctl', '--user']
        shown = run([*prefix, 'show', 'endpoint-user-sensor.service',
            '--property=LoadState,UnitFileState,FragmentPath,ActiveState,DropInPaths']).decode()
        props = dict(row.split('=', 1) for row in shown.splitlines() if '=' in row)
        if not eligible_owned_unit(props):
            continue
        run([*prefix, 'daemon-reload'])
        # Preserve boot policy: restart active autostart service; never enable it.
        run([*prefix, 'stop' if stop else 'restart', 'endpoint-user-sensor.service'], timeout=25)
        restarted.append(uid)
    return restarted
