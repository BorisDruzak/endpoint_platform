"""Seal final RPM buildroot AFTER all bytes exist, BEFORE signing the archives."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat

SENSOR_FILES = {'/usr/lib/endpoint-agent/endpoint-kde-probe', '/usr/lib/endpoint-agent/start-user-sensor',
    '/usr/lib/endpoint-agent/browser-bridge', '/usr/lib/endpoint-agent/browser-policy-helper',
    '/usr/lib/systemd/system/endpoint-agent-browser-policy.service',
    '/usr/lib/systemd/user/endpoint-user-sensor.service', '/etc/xdg/autostart/endpoint-user-sensor.desktop',
    '/usr/share/endpoint-agent/extension-id.txt', '/usr/share/endpoint-agent/foreground.js'}
SENSOR_PREFIXES = ('/usr/lib/endpoint-agent/policy-helper/', '/etc/chromium/native-messaging-hosts/', '/etc/opt/chrome/native-messaging-hosts/')
META = {'endpoint-agent':'/usr/share/endpoint-agent/native-source.json',
    'endpoint-agent-user-sensor':'/usr/share/endpoint-agent-user-sensor/native-source.json'}


def build_manifest(root, *, version, revision, sensor):
    if version != '3.2.178' or not re.fullmatch('[0-9a-f]{40}', revision):
        raise ValueError('NEW_REVIEWED_NATIVE_SOURCE_REQUIRED')
    root = Path(root)
    core = (root/f'opt/endpoint-agent/versions/{version}/manifest.json').read_bytes()
    if json.loads(core)['source_revision'] != revision:
        raise ValueError('CORE_SOURCE_MISMATCH')
    packages = {'endpoint-agent': {}, 'endpoint-agent-user-sensor': {}}
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ValueError('UNSAFE_NATIVE_PAYLOAD')
        if path.is_dir():
            continue
        name = '/' + path.relative_to(root).as_posix()
        if name in META.values():
            continue
        package = 'endpoint-agent-user-sensor' if name in SENSOR_FILES or name.startswith(SENSOR_PREFIXES) else 'endpoint-agent'
        if package == 'endpoint-agent-user-sensor' and not sensor:
            raise ValueError('UNDECLARED_SENSOR_PAYLOAD')
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o7022:
            raise ValueError('UNSAFE_NATIVE_MODE')
        packages[package][name] = {'sha256':hashlib.sha256(path.read_bytes()).hexdigest(), 'mode':f'{mode:04o}'}
    result = {'schema_version':'endpoint_linux_native_source_v1', 'version':version,
        'source_revision':revision, 'core_manifest_sha256':hashlib.sha256(core).hexdigest(), 'packages':packages}
    raw = (json.dumps(result, sort_keys=True, separators=(',', ':'))+'\n').encode()
    for package, name in META.items():
        if package == 'endpoint-agent-user-sensor' and not sensor:
            continue
        target = root/name.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        target.chmod(0o644)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--sensor', action='store_true')
    args = parser.parse_args()
    build_manifest(args.root, version=args.version, revision=args.revision, sensor=args.sensor)
