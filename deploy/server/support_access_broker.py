#!/usr/bin/env python3
"""Root-owned, stdlib-only reconciler for narrowly bounded SSH tunnel leases.

Install this file root:root outside the application release. The unprivileged
exporter supplies only validated UUIDs, Ed25519 public keys and reserved ports.
No app-provided path, executable, shell text or UID is ever executed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Callable
from uuid import UUID

SNAPSHOT = Path('/run/endpoint-support/leases.json')
STATE_ROOT = Path('/var/lib/endpoint-support-broker')
KEYS_ROOT = Path('/etc/endpoint-support/authorized_keys')
GATEWAY_CONFIG = Path('/etc/endpoint-support/sshd_config')
GROUP = 'endpoint-support'


@dataclass(frozen=True)
class Lease:
    device_id: str
    tunnel_user: str
    remote_port: int
    tunnel_public_key: str
    host_public_key: str
    expires_at: datetime


def _time(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError('INVALID_TIMESTAMP')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('INVALID_TIMESTAMP')
    return parsed.astimezone(UTC)


def _key(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]{68}', value):
        raise ValueError('INVALID_PUBLIC_KEY')
    blob = base64.b64decode(value.split()[1], validate=True)
    if len(blob) != 51 or blob[:19] != struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32):
        raise ValueError('INVALID_PUBLIC_KEY')
    return value


def _username(device_id: str) -> str:
    value = UUID(device_id)
    if str(value) != device_id:
        raise ValueError('INVALID_DEVICE_ID')
    return 'eps-' + value.hex[:24]


def validate_snapshot(data: object, *, now: datetime) -> tuple[Lease, ...]:
    if not isinstance(data, dict) or set(data) != {'schema_version', 'generated_at', 'valid_until', 'leases'} or data['schema_version'] != 1:
        raise ValueError('INVALID_SNAPSHOT')
    generated, deadline = _time(data['generated_at']), _time(data['valid_until'])
    if generated > now+timedelta(seconds=5) or not generated < deadline <= generated+timedelta(seconds=60) or not generated-timedelta(seconds=5) <= now < deadline:
        raise ValueError('STALE_SNAPSHOT')
    rows = data['leases']
    if not isinstance(rows, list) or len(rows) > 1000:
        raise ValueError('INVALID_LEASES')
    leases = []
    devices, users, ports, keys = set(), set(), set(), set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {'device_id', 'tunnel_user', 'remote_port', 'tunnel_public_key', 'host_public_key', 'expires_at'}:
            raise ValueError('INVALID_LEASE')
        device = row['device_id']
        if not isinstance(device, str) or row['tunnel_user'] != _username(device):
            raise ValueError('INVALID_TUNNEL_USER')
        port = row['remote_port']
        if type(port) is not int or not 32000 <= port <= 41999:
            raise ValueError('INVALID_TUNNEL_PORT')
        tunnel_key, host_key = _key(row['tunnel_public_key']), _key(row['host_public_key'])
        expiry = _time(row['expires_at'])
        if expiry <= now or expiry > generated+timedelta(hours=24, seconds=5):
            raise ValueError('EXPIRED_LEASE')
        if device in devices or row['tunnel_user'] in users or port in ports or tunnel_key in keys:
            raise ValueError('CONFLICTING_LEASE')
        devices.add(device); users.add(row['tunnel_user']); ports.add(port); keys.add(tunnel_key)
        leases.append(Lease(device, row['tunnel_user'], port, tunnel_key, host_key, expiry))
    return tuple(leases)


def authorized_key(lease: Lease) -> str:
    return f'restrict,port-forwarding,permitlisten="127.0.0.1:{lease.remote_port}" {lease.tunnel_public_key}\n'


def render_gateway_config(listen_address: str) -> str:
    address = ipaddress.ip_address(listen_address)
    if address.version != 4 or not address.is_private or address.is_unspecified or address.is_multicast or address.is_loopback:
        raise ValueError('LAN_LISTEN_ADDRESS_REQUIRED')
    # A separate complete sshd config cannot inherit the administrator daemon's
    # Match blocks, alternative authorized key sources, or forwarding grants.
    return ('# Owned by Endpoint Support Access; do not edit.\n'
            'Port 2222\n'
            f'ListenAddress {address}\n'
            'AddressFamily inet\n'
            'PidFile /run/endpoint-support-gateway.pid\n'
            'HostKey /etc/ssh/ssh_host_ed25519_key\n'
            'AllowGroups endpoint-support\n'
            'AllowUsers eps-*\n'
            'AuthorizedKeysFile /etc/endpoint-support/authorized_keys/%u\n'
            'AuthorizedKeysCommand none\n'
            'TrustedUserCAKeys none\n'
            'AuthenticationMethods publickey\n'
            'PubkeyAuthentication yes\n'
            'PasswordAuthentication no\n'
            'KbdInteractiveAuthentication no\n'
            'UsePAM yes\n'
            'PermitRootLogin no\n'
            'AllowTcpForwarding remote\n'
            'AllowStreamLocalForwarding no\n'
            'PermitOpen none\n'
            'GatewayPorts no\n'
            'PermitTunnel no\n'
            'AllowAgentForwarding no\n'
            'X11Forwarding no\n'
            'PermitTTY no\n'
            'PermitUserRC no\n'
            'MaxSessions 0\n'
            'MaxAuthTries 3\n'
            'LoginGraceTime 20\n'
            'ClientAliveInterval 15\n'
            'ClientAliveCountMax 2\n'
            'LogLevel VERBOSE\n'
            'ForceCommand /usr/sbin/nologin\n')


def _check_path(path: Path) -> None:
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError('UNSAFE_PATH')


def _atomic(path: Path, text: str, mode: int = 0o600) -> None:
    _check_path(path)
    descriptor, temporary = tempfile.mkstemp(prefix='.endpoint-', dir=path.parent)
    try:
        os.fchmod(descriptor, mode) if hasattr(os, 'fchmod') else None
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as output:
            output.write(text); output.flush(); os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def _load_state(path: Path) -> dict[str, str]:
    _check_path(path)
    if not path.exists(): return {}
    if path.stat().st_size > 256_000: raise ValueError('INVALID_BROKER_STATE')
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict) or len(data) > 1000 or any(not re.fullmatch(r'eps-[0-9a-f]{24}', key) or not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value) for key, value in data.items()):
        raise ValueError('INVALID_BROKER_STATE')
    return data


def reconcile(leases: tuple[Lease, ...], *, state_path: Path, keys_root: Path,
              ensure_user: Callable[[Lease], None], disconnect: Callable[[str], None]) -> None:
    try:
        old = _load_state(state_path)
    except (ValueError, json.JSONDecodeError):
        old = {}
    _check_path(keys_root)
    # Recover the write-before-state crash window using our own fixed key
    # directory. Never infer ownership from a name outside this directory.
    for path in keys_root.iterdir():
        if re.fullmatch(r'eps-[0-9a-f]{24}', path.name):
            _check_path(path)
            if path.is_file():
                old.setdefault(path.name, '')
    new = {lease.tunnel_user: hashlib.sha256(authorized_key(lease).encode()).hexdigest() for lease in leases}
    # Remove authorization before terminating old sessions. A crash cannot
    # leave a revoked key able to authenticate again.
    for user in old.keys()-new.keys():
        _atomic(keys_root/user, '', 0o644)
        disconnect(user)
        # An empty file remains a durable disconnect obligation until this
        # succeeds. Recover it even if the state journal never existed.
        (keys_root/user).unlink()
    for lease in leases:
        ensure_user(lease)
        if old.get(lease.tunnel_user) != new[lease.tunnel_user]:
            if lease.tunnel_user in old:
                _atomic(keys_root/lease.tunnel_user, '', 0o644)
                disconnect(lease.tunnel_user)
            _atomic(keys_root/lease.tunnel_user, authorized_key(lease), 0o644)
    _atomic(state_path, json.dumps(new, sort_keys=True)+'\n')


def _run(*args: str, allowed: tuple[int, ...] = (0,)) -> None:
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    if result.returncode not in allowed:
        raise RuntimeError('BROKER_COMMAND_FAILED')


def _owned_user(user: str):
    import grp
    import pwd
    account = pwd.getpwnam(user)
    group = grp.getgrnam(GROUP)
    if not re.fullmatch(r'eps-[0-9a-f]{24}', user) or account.pw_gid != group.gr_gid or not account.pw_gecos.startswith('Endpoint support ') or account.pw_dir != '/nonexistent' or account.pw_shell != '/usr/sbin/nologin' or account.pw_uid < 100:
        raise ValueError('UNOWNED_TUNNEL_USER')
    return account


def ensure_system_user(lease: Lease) -> None:
    import grp
    import pwd
    try: grp.getgrnam(GROUP)
    except KeyError: _run('/usr/sbin/groupadd', '--system', GROUP)
    try: pwd.getpwnam(lease.tunnel_user)
    except KeyError:
        _run('/usr/sbin/useradd', '--system', '--no-create-home', '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', '--gid', GROUP, '--comment', 'Endpoint support '+lease.device_id, lease.tunnel_user)
    account = _owned_user(lease.tunnel_user)
    if account.pw_gecos != 'Endpoint support '+lease.device_id:
        raise ValueError('TUNNEL_USER_CONFLICT')


def disconnect_system_user(user: str) -> None:
    try: account = _owned_user(user)
    except KeyError: return
    _run('/usr/bin/pkill', '-KILL', '-u', str(account.pw_uid), allowed=(0, 1))


def initialize_directories() -> None:
    # Explicit parents: mkdir(parents=True) plus root's0077 umask would otherwise
    # create an untraversable0700 parent that blocks sshd's unprivileged key read.
    for path, mode in ((STATE_ROOT, 0o700), (KEYS_ROOT.parent, 0o755), (KEYS_ROOT, 0o755)):
        _check_path(path)
        path.mkdir(mode=mode, exist_ok=True)
        if path.stat().st_uid != 0:
            raise ValueError('UNOWNED_BROKER_DIRECTORY')
        os.chmod(path, mode)


def install_gateway(listen_address: str) -> None:
    _atomic(GATEWAY_CONFIG, render_gateway_config(listen_address), 0o600)
    _run('/usr/sbin/sshd', '-t', '-f', str(GATEWAY_CONFIG))


def main() -> int:
    if os.name != 'posix' or os.geteuid() != 0: raise SystemExit('ROOT_REQUIRED')
    parser = argparse.ArgumentParser()
    parser.add_argument('--install-gateway', metavar='LAN_IPV4')
    parser.add_argument('--clear', action='store_true')
    args = parser.parse_args()
    import fcntl
    initialize_directories()
    with (STATE_ROOT/'broker.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            _check_path(SNAPSHOT)
            if SNAPSHOT.stat().st_size > 1_000_000: raise ValueError('SNAPSHOT_TOO_LARGE')
            leases = validate_snapshot(json.loads(SNAPSHOT.read_text(encoding='utf-8')), now=datetime.now(UTC))
        except (OSError, ValueError, TypeError):
            leases = ()  # Missing, stale or malformed policy revokes every owned lease.
        if args.clear: leases = ()
        if args.install_gateway: install_gateway(args.install_gateway)
        reconcile(leases, state_path=STATE_ROOT/'state.json', keys_root=KEYS_ROOT, ensure_user=ensure_system_user, disconnect=disconnect_system_user)
    return 0


if __name__ == '__main__':
    try: raise SystemExit(main())
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired): raise SystemExit('SUPPORT_BROKER_FAILED')
