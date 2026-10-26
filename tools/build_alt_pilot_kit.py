#!/usr/bin/env python3
"""Build/verify the fixed signed ALT 11 distribution kit; never enroll or deploy."""
from __future__ import annotations

import argparse
import gzip
import hashlib
from io import BytesIO
import json
from pathlib import Path
import platform
import os
import tempfile
import re
import shlex
import stat
import subprocess
import tarfile

VERSION = '3.2.156'
AGENT_REVISION = '6ed41cd01d494e46111a452c2ae3a844f723175b'
KIT_NAME = 'endpoint-alt-pilot-3.2.156-1'
ORIGIN = 'https://endpoint.sosnadmin.local'
SCHEMA = 'endpoint_alt_pilot_kit_v2'
RUNTIME = f'endpoint-agent-linux_amd64-{VERSION}.tar.gz'
RUNTIME_MANIFEST = f'endpoint-agent-linux_amd64-{VERSION}.manifest.json'
PACKAGES = {
    f'endpoint-agent-{VERSION}-alt5.x86_64.rpm': ('endpoint-agent', VERSION, 'alt5', 'x86_64', '(none)'),
    f'endpoint-agent-user-sensor-{VERSION}-alt5.x86_64.rpm': ('endpoint-agent-user-sensor', VERSION, 'alt5', 'x86_64', '(none)'),
    'cups-browsed-2.1.1-alt1.endpoint2.x86_64.rpm': ('cups-browsed', '2.1.1', 'alt1.endpoint2', 'x86_64', '(none)'),
    'cups-browsed-2.1.1-alt1.x86_64.rpm': ('cups-browsed', '2.1.1', 'alt1', 'x86_64', '(none)'),
    'cups-browsed-2.1.1-alt1.src.rpm': ('cups-browsed', '2.1.1', 'alt1', 'x86_64', '1'),
    'cups-browsed-2.1.1-alt1.endpoint2.src.rpm': ('cups-browsed', '2.1.1', 'alt1.endpoint2', 'x86_64', '1'),
}
ASSETS = ('README.ru.md', 'rebuild-cups.sh', 'cups-browsed-fix-67.patch', 'cups-browsed-fix-is-disabled.patch',
          'staging-config.example.yaml', 'staging.conf', 'production-config.example.yaml', 'production.conf', 'endpoint-rpm-release.asc')
FILES = {*PACKAGES, RUNTIME, RUNTIME_MANIFEST, *ASSETS, 'verify-kit.py'}
INSTALL = tuple(list(PACKAGES)[:3])
MAX_FILE = 256 * 1024 * 1024
SYSTEM_ROOT = Path('/')
PUBLISHER_FINGERPRINT = 'BC24B8EE43DBB05A748E11A4343B5DA748370631'
PUBLISHER_KEY_SHA256 = '12175df39caa5a67336aeb002b5c71d3a9d3047961f5ad90cf959650044b456c'
SIGNED_PACKAGES = (*INSTALL, 'cups-browsed-2.1.1-alt1.endpoint2.src.rpm')
QUALIFIED_INPUTS = {
    'endpoint-agent-3.2.156-alt5.x86_64.rpm': '0287f55321b7f69ce5f3036c866ff416af376c907a087052afb0f833cade0e9b',
    'endpoint-agent-user-sensor-3.2.156-alt5.x86_64.rpm': '5688d7270c647fe87b2ce3ff37150c867d08dccc358b320e65e8fb58ef126daa',
    RUNTIME: 'c2fb732693884e7779a95cf9fbbc931d5fd7253435ecb7483c5e722162981370',
    RUNTIME_MANIFEST: '94f1b5242963a5b5ead2f41ac4c9a1b567ae490c42f89bb9c67e50d927529694',
    'cups-browsed-2.1.1-alt1.endpoint2.x86_64.rpm': 'f07200cab984e888c791114f98fac1f11e08b8f2c25aa50ec6a3939972a6a86e',
    'cups-browsed-2.1.1-alt1.x86_64.rpm': 'a21146530c236ceae04155c879b468923808c64238ee550c942dabc985974018',
    'cups-browsed-2.1.1-alt1.src.rpm': '4276876f261f2719ff3d453551af3c462f54a2ad963f4394d9b24509309ff624',
    'cups-browsed-2.1.1-alt1.endpoint2.src.rpm': 'c4fc8602708132be5fc12156b693773716d4d89bb059321fd93da00a45e57612',
}


def read_regular(path: Path) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_FILE:
        raise ValueError('REGULAR_FILE_REQUIRED')
    with path.open('rb') as stream:
        result = stream.read(MAX_FILE + 1)
    if len(result) > MAX_FILE:
        raise ValueError('FILE_SIZE')
    return result


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def query_rpm(path: Path) -> tuple[str, ...]:
    result = subprocess.run(['rpm', '-qp', '--qf', '%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCEPACKAGE}', str(path)],
        check=True, capture_output=True, text=True, timeout=30)
    return tuple(result.stdout.strip().split('\t'))


def verify_package_signatures(root: Path, key: Path) -> None:
    if sha(read_regular(key)) != PUBLISHER_KEY_SHA256:
        raise ValueError('PUBLISHER_KEY_DIGEST')
    environment = {**os.environ, 'LC_ALL': 'C'}
    with tempfile.TemporaryDirectory(prefix='endpoint-rpm-trust-') as database:
        for command in (['rpm', '--dbpath', database, '--initdb'],
                        ['rpm', '--dbpath', database, '--import', str(key)]):
            subprocess.run(command, check=True, capture_output=True, text=True, timeout=30, env=environment)
        for name in SIGNED_PACKAGES:
            result = subprocess.run(['rpm', '--dbpath', database, '--checksig', '--verbose', str(root / name)],
                capture_output=True, text=True, timeout=30, env=environment)
            suffix = re.escape(PUBLISHER_FINGERPRINT[-8:].lower())
            header = re.search(r'Header V4 RSA/SHA256 Signature, key ID ' + suffix + r': OK', result.stdout)
            payload = re.search(r'(?m)^\s*V4 RSA/SHA256 Signature, key ID ' + suffix + r': OK', result.stdout)
            if result.returncode or not header or not payload:
                raise ValueError('RPM_SIGNATURE_REQUIRED')


def build(inputs: Path, output: Path) -> tuple[Path, Path]:
    if inputs.is_symlink() or not inputs.is_dir() or {p.name for p in inputs.iterdir()} != {*PACKAGES, RUNTIME, RUNTIME_MANIFEST}:
        raise ValueError('INPUT_SET')
    payload = {name: read_regular(inputs / name) for name in (*PACKAGES, RUNTIME, RUNTIME_MANIFEST)}
    if output.resolve().is_relative_to(inputs.resolve()):
        raise ValueError('OUTPUT_INSIDE_INPUTS')
    for name, expected in PACKAGES.items():
        if query_rpm(inputs / name) != expected:
            raise ValueError('RPM_IDENTITY')
    artifact = json.loads(payload[RUNTIME_MANIFEST])
    if (artifact.get('schema_version') != 'endpoint_linux_agent_artifact_v1'
        or artifact.get('version') != VERSION or artifact.get('platform') != 'linux_amd64'
        or artifact.get('artifact_name') != RUNTIME
        or artifact.get('source_revision') != AGENT_REVISION):
        raise ValueError('RUNTIME_IDENTITY')
    if artifact.get('sha256') != sha(payload[RUNTIME]) or artifact.get('size') != len(payload[RUNTIME]):
        raise ValueError('RUNTIME_DIGEST')
    if any(sha(payload[name]) != expected for name, expected in QUALIFIED_INPUTS.items()):
        raise ValueError('QUALIFIED_DIGEST')
    asset_root = Path(__file__).resolve().parents[1] / 'packaging' / 'alt' / 'pilot'
    payload.update({name: read_regular(asset_root / name) for name in ASSETS})
    verify_package_signatures(inputs, asset_root / 'endpoint-rpm-release.asc')
    payload['verify-kit.py'] = read_regular(Path(__file__).resolve())
    manifest = {'schema_version': SCHEMA, 'kit_name': KIT_NAME, 'agent_version': VERSION,
        'agent_source_revision': artifact['source_revision'], 'endpoint_origin': ORIGIN,
        'purpose': 'qualified-native-production-distribution', 'install_packages': list(INSTALL),
        'signature_status': 'publisher-rpm-signatures-verified', 'publisher_fingerprint': PUBLISHER_FINGERPRINT,
        'signed_packages': list(SIGNED_PACKAGES),
        'files': {name: {'sha256': sha(data), 'size': len(data), 'mode': '0755' if name.endswith('.sh') else '0644'}
            for name, data in sorted(payload.items())}}
    payload['pilot-manifest.json'] = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    data = BytesIO()
    with gzip.GzipFile(fileobj=data, mode='wb', filename='', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, value in sorted(payload.items()):
                info = tarfile.TarInfo(KIT_NAME + '/' + name)
                info.mode = 0o755 if name.endswith('.sh') else 0o644
                info.size = len(value)
                archive.addfile(info, BytesIO(value))
    output.mkdir(parents=True, exist_ok=True)
    archive = output / (KIT_NAME + '.tar.gz')
    digest = output / (archive.name + '.sha256')
    hashes = output / (KIT_NAME + '.manifest.sha256')
    outputs = {archive: data.getvalue(), digest: (sha(data.getvalue()) + '  ' + archive.name + '\n').encode(),
        hashes: (sha(payload['pilot-manifest.json']) + '  pilot-manifest.json\n').encode()}
    for path, value in outputs.items():
        if path.exists() or path.is_symlink():
            if read_regular(path) != value:
                raise ValueError('IMMUTABLE_OUTPUT')
    for path, value in outputs.items():
        if not path.exists():
            with path.open('xb') as stream:
                stream.write(value)
    return archive, digest


def verify(root: Path, expected: str) -> dict:
    if re.fullmatch('[0-9a-f]{64}', expected) is None:
        raise ValueError('MANIFEST_DIGEST')
    raw = read_regular(root / 'pilot-manifest.json')
    if sha(raw) != expected:
        raise ValueError('MANIFEST_DIGEST')
    manifest = json.loads(raw)
    if (manifest.get('schema_version') != SCHEMA or manifest.get('kit_name') != KIT_NAME
        or manifest.get('agent_version') != VERSION or manifest.get('endpoint_origin') != ORIGIN
        or manifest.get('agent_source_revision') != AGENT_REVISION
        or manifest.get('install_packages') != list(INSTALL)
        or manifest.get('publisher_fingerprint') != PUBLISHER_FINGERPRINT
        or manifest.get('signed_packages') != list(SIGNED_PACKAGES)
        or manifest.get('signature_status') != 'publisher-rpm-signatures-verified'):
        raise ValueError('MANIFEST_IDENTITY')
    if set(manifest.get('files', {})) != FILES or {p.name for p in root.iterdir()} != FILES | {'pilot-manifest.json'}:
        raise ValueError('FILE_SET')
    for name, meta in manifest['files'].items():
        value = read_regular(root / name)
        if meta.get('sha256') != sha(value) or meta.get('size') != len(value):
            raise ValueError('FILE_DIGEST')
        if name in QUALIFIED_INPUTS and sha(value) != QUALIFIED_INPUTS[name]:
            raise ValueError('QUALIFIED_DIGEST')
    verify_package_signatures(root, root / 'endpoint-rpm-release.asc')
    return manifest


def machine_install_packages(facts: dict, expected_hostname: str) -> list[str]:
    if expected_hostname != facts['hostname'] or not expected_hostname:
        raise ValueError('HOSTNAME_MISMATCH')
    if (facts['os_id'] not in {'altlinux', 'altlinux-workstation', 'altlinux-server'}
        or re.fullmatch(r'11(?:\.\d+)*', facts['os_version']) is None or facts['arch'] != 'x86_64'):
        raise ValueError('ALT11_X86_64_REQUIRED')
    if facts['state_exists'] or facts['agent_query_status'] != 1:
        raise ValueError('EXISTING_AGENT_STATE_PRESERVED')
    if facts['cups'] not in {None, '2.1.1-alt1.x86_64', '2.1.1-alt1.endpoint2.x86_64'}:
        raise ValueError('CUPS_VERSION_NOT_REVIEWED')
    return list(INSTALL[:2] if facts['cups'] == '2.1.1-alt1.endpoint2.x86_64' else INSTALL)


def machine_preflight(root: Path, expected_hostname: str) -> dict:
    release = {}
    for line in (SYSTEM_ROOT / 'etc/os-release').read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            release[key] = shlex.split(value)[0] if value else ''
    state_paths = [SYSTEM_ROOT / path for path in (
        'opt/endpoint-agent', 'var/lib/endpoint-agent', 'var/log/endpoint-agent',
        'etc/endpoint-agent', 'etc/credstore/endpoint-enrollment-claim', 'usr/lib/endpoint-agent')]
    for directory in ('etc/systemd/system', 'run/systemd/system', 'usr/lib/systemd/system',
                      'etc/systemd/user', 'usr/lib/systemd/user', 'etc/xdg/autostart'):
        for pattern in ('endpoint-agent*', 'endpoint-user-sensor*'):
            state_paths.extend((SYSTEM_ROOT / directory).glob(pattern))
    state = any(path.exists() or path.is_symlink() for path in state_paths)
    existing = subprocess.run(['rpm', '-q', 'endpoint-agent'], capture_output=True, timeout=15)
    cups = subprocess.run(['rpm', '-q', '--qf', '%{VERSION}-%{RELEASE}.%{ARCH}', 'cups-browsed'],
        capture_output=True, text=True, timeout=15)
    if cups.returncode not in (0, 1):
        raise ValueError('CUPS_RPM_QUERY_FAILURE')
    packages = machine_install_packages({'hostname': platform.node(), 'os_id': release.get('ID', ''),
        'os_version': release.get('VERSION_ID', ''), 'arch': platform.machine(), 'state_exists': state,
        'agent_query_status': existing.returncode, 'cups': cups.stdout.strip() if cups.returncode == 0 else None}, expected_hostname)
    for name, expected in PACKAGES.items():
        if query_rpm(root / name) != expected:
            raise ValueError('RPM_IDENTITY')
    # --test executes no install scriptlets and changes no installed package.
    result = subprocess.run(['rpm', '-Uvh', '--test', *(str(root / name) for name in packages)],
        capture_output=True, timeout=60)
    if result.returncode:
        raise ValueError('RPM_TRANSACTION_PREFLIGHT_FAILED; run rpm -Uvh --test on the three documented packages for dependency details')
    return {'platform': 'ALT11_x86_64', 'clean_endpoint_state': True, 'rpm_transaction_test': 'passed',
        'changes_performed': False, 'endpoint_origin': ORIGIN, 'install_packages': packages}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    creator = commands.add_parser('build')
    creator.add_argument('--inputs', type=Path, required=True)
    creator.add_argument('--output', type=Path, required=True)
    checker = commands.add_parser('check')
    checker.add_argument('--root', type=Path, default=Path(__file__).resolve().parent)
    checker.add_argument('--expected-manifest-sha256', required=True)
    checker.add_argument('--test-hostname')
    args = parser.parse_args()
    try:
        if args.command == 'build':
            archive, digest = build(args.inputs, args.output)
            print(json.dumps({'archive': str(archive), 'sha256_file': str(digest)}))
        else:
            verify(args.root, args.expected_manifest_sha256)
            result = {'kit_integrity': 'passed', 'endpoint_origin': ORIGIN}
            if args.test_hostname is not None:
                result.update(machine_preflight(args.root, args.test_hostname))
            print(json.dumps(result))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        # Report bounded operator errors, never arbitrary RPM/remote bodies.
        print(str(error)[:240], file=__import__('sys').stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
