#!/usr/bin/python3
"""Select the same root-protected Core release in credential-free user mode."""
import os
from pathlib import Path
import re
import subprocess
import sys
import stat
from uuid import uuid4


def write_session_environment() -> None:
    runtime = Path(f'/run/user/{os.getuid()}')
    info = runtime.lstat()
    if not stat.S_ISDIR(info.st_mode) or runtime.resolve() != runtime or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('unsafe user runtime directory')
    names = ('DISPLAY', 'WAYLAND_DISPLAY', 'XAUTHORITY', 'XDG_SESSION_TYPE',
             'XDG_CURRENT_DESKTOP', 'DBUS_SESSION_BUS_ADDRESS')
    rows = []
    for name in names:
        value = os.environ.get(name, '')
        if len(value) > 2048 or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError('invalid graphical environment')
        quoted = value.replace('\\', '\\\\').replace('"', '\\"')
        rows.append(f'{name}="{quoted}"\n')
    stage = runtime / f'.endpoint-user-sensor-{uuid4().hex}.tmp'
    try:
        descriptor = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as output:
            output.write(''.join(rows))
            output.flush()
            os.fsync(output.fileno())
        os.replace(stage, runtime / 'endpoint-user-sensor.env')
    finally:
        stage.unlink(missing_ok=True)


def main() -> int:
    if os.getuid() == 0 or os.geteuid() != os.getuid():
        return 1
    try:
        if sys.argv[1:] == ['--autostart']:
            write_session_environment()
            subprocess.run(['systemctl', '--user', 'restart', 'endpoint-user-sensor.service'], check=True, timeout=20)
            return 0
        if sys.argv[1:]:
            return 1
        if not os.environ.get('DISPLAY') and not os.environ.get('WAYLAND_DISPLAY'):
            return 78
        result = subprocess.run(
            ['/usr/lib/endpoint-agent/check-start-prerequisites', '--print-selected-version'],
            capture_output=True, check=True, timeout=5,
        )
        if len(result.stdout) > 128:
            return 1
        version = result.stdout.decode('ascii').strip()
        if re.fullmatch(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)', version) is None:
            return 1
        executable = Path('/opt/endpoint-agent/versions') / version / 'endpoint-agent/endpoint-agent'
        os.execv(executable, [str(executable), '--linux-user-sensor'])
    except (OSError, ValueError, subprocess.SubprocessError):
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
