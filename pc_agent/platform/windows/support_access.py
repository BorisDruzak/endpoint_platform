"""Independent support-access policy and lifecycle; no Agent/Core imports.

Only bounded HTTPS policy and native OpenSSH children are interpreted here.
No command endpoint, source execution, Core health gate or update receipt exists.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import re
import uuid

COMPONENT_VERSION = '1.1.5'
RESTORED_ACTIVATION_CODES = frozenset({
    'support_activation_image_restored',
    'support_activation_start_restored',
    'support_activation_readiness_restored',
})
SERVICE_NAME = 'EndpointSupportAccess'
MAX_LEASE_SECONDS = 86400
LOCAL_PORT = 22222


def public_key(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]+={0,2}', value):
        raise ValueError('invalid_support_key')
    try:
        blob = base64.b64decode(value.split()[1], validate=True)
    except ValueError as error:
        raise ValueError('invalid_support_key') from error
    if len(blob) != 51 or blob[:19] != b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20':
        raise ValueError('invalid_support_key')
    if base64.b64encode(blob).decode() != value.split()[1]:
        raise ValueError('invalid_support_key')
    return value


def _integer(value: object, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('invalid_support_policy')
    return value


def _name(value: object, pattern: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise ValueError('invalid_support_policy')
    return value


@dataclass(frozen=True)
class SupportPolicy:
    device_id: str
    enabled: bool
    revision: int
    expires_at: datetime | None = None
    gateway_host: str = ''
    gateway_port: int = 22
    gateway_host_public_key: str = ''
    tunnel_user: str = ''
    remote_port: int = 0
    local_port: int = LOCAL_PORT
    windows_admin_username: str = ''
    operator_public_keys: tuple[str, ...] = ()
    poll_after_seconds: int = 30

    @classmethod
    def parse(cls, raw: dict, *, device_id: str, now: datetime) -> 'SupportPolicy':
        if not isinstance(raw, dict) or raw.get('device_id') != device_id or str(uuid.UUID(device_id)) != device_id:
            raise ValueError('invalid_support_policy')
        if type(raw.get('enabled')) is not bool:
            raise ValueError('invalid_support_policy')
        revision = _integer(raw.get('revision'), 0, 2**63-1)
        if not raw['enabled']:
            return cls(device_id, False, revision)
        expiry = datetime.fromisoformat(raw['expires_at'].replace('Z', '+00:00'))
        if expiry.tzinfo is None or not 0 < (expiry-now).total_seconds() <= MAX_LEASE_SECONDS:
            raise ValueError('invalid_support_policy')
        host = _name(raw.get('gateway_host'), r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?')
        # Canonical hostname only; an IP or malformed DNS label must fail closed.
        if '.' not in host or any(not label or len(label)>63 or label.startswith('-') or label.endswith('-') for label in host.split('.')):
            raise ValueError('invalid_support_policy')
        try:
            import ipaddress
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError('invalid_support_policy')
        user = 'eps-' + uuid.UUID(device_id).hex[:24]
        if raw.get('tunnel_user') != user:
            raise ValueError('invalid_support_policy')
        keys = raw.get('operator_public_keys')
        if not isinstance(keys, list) or not 1 <= len(keys) <= 16:
            raise ValueError('invalid_support_policy')
        login = _name(raw.get('windows_admin_username'), r'(?=.{1,64}$)(?:[A-Za-z0-9][A-Za-z0-9_-]{0,14}\\)?[A-Za-z0-9][A-Za-z0-9_.-]{0,63}')
        login = login.lower() if '\\' in login else login
        local_port = _integer(raw.get('local_port'), LOCAL_PORT, LOCAL_PORT)
        return cls(device_id, True, revision, expiry, host,
                   _integer(raw.get('gateway_port'), 1, 65535), public_key(raw.get('gateway_host_public_key')),
                   user, _integer(raw.get('remote_port'), 32000, 41999), local_port, login,
                   tuple(public_key(k) for k in keys), _integer(raw.get('poll_after_seconds',30), 5, 60))


def _ssh_path(path: Path) -> str:
    value = str(path).replace('\\', '/')
    if any(ch in value for ch in '\r\n"'):
        raise ValueError('invalid_support_path')
    return '"' + value + '"'


def windows_ssh_principal(value: str) -> str:
    """Windows OpenSSH matches lowercase short-domain SAM names, without globs."""
    return _name(value,r'(?=.{1,64}$)(?:[A-Za-z0-9][A-Za-z0-9_-]{0,14}\\)?[A-Za-z0-9][A-Za-z0-9_.-]{0,63}').lower()


def sshd_config(root: Path, p: SupportPolicy) -> str:
    return '\n'.join([
        f'Port {p.local_port}', 'AddressFamily inet', 'ListenAddress 127.0.0.1',
        f'HostKey {_ssh_path(root / "host_ed25519")}',
        f'AuthorizedKeysFile {_ssh_path(root / "authorized_keys")}',
        f'PidFile {_ssh_path(root / "sshd.pid")}',
        f'AllowUsers {windows_ssh_principal(p.windows_admin_username)}', 'PubkeyAuthentication yes',
        'PasswordAuthentication no', 'KbdInteractiveAuthentication no',
        'AuthenticationMethods publickey', 'AllowAgentForwarding no', 'AllowTcpForwarding no',
        'GatewayPorts no', 'PermitTunnel no', 'PermitUserEnvironment no',
        'StrictModes yes', 'LogLevel INFO', 'MaxAuthTries 3', 'LoginGraceTime 30',
        'ClientAliveInterval 15', 'ClientAliveCountMax 2', '',
    ])


def tunnel_command(ssh: str, root: Path, p: SupportPolicy) -> list[str]:
    return [ssh, '-F', 'NUL', '-N', '-T', '-v', '-i', str(root/'tunnel_ed25519'),
            '-p', str(p.gateway_port), '-l', p.tunnel_user,
            '-R', f'127.0.0.1:{p.remote_port}:127.0.0.1:{p.local_port}',
            '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'HostKeyAlias=endpoint-support-gateway',
            '-o', f'UserKnownHostsFile={_ssh_path(root / "known_hosts")}', '-o', 'GlobalKnownHostsFile=NUL',
            '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=15',
            '-o', 'ServerAliveCountMax=2', '-o', 'ConnectTimeout=10',
            '-o', 'ConnectionAttempts=1', '-o', 'ForwardAgent=no',
            '-o', 'ClearAllForwardings=no', p.gateway_host]


class SupportSupervisor:
    """Monotonic fail-closed lease independent of HTTP timeout or wall-clock rollback."""
    def __init__(self, device_id: str, children):
        self.device_id = device_id
        self.children = children
        self.policy = None
        self.deadline = 0.0
        self.retry_at = 0.0
        self.failures = 0
        self.state = 'disabled'

    def accept(self, raw: dict, *, now: datetime, monotonic_now: float) -> None:
        try:
            p = SupportPolicy.parse(raw, device_id=self.device_id, now=now)
            if self.policy and p.revision < self.policy.revision:
                raise ValueError('stale_support_policy')
        except (ValueError, KeyError, TypeError, AttributeError):
            self.stop('invalid_policy')
            raise ValueError('invalid_support_policy') from None
        if not p.enabled:
            self.policy = p
            self.stop('disabled')
            return
        changed = self.policy is None or p != self.policy
        if changed:
            self.children.stop()
        self.policy = p
        self.deadline = monotonic_now + min(60, (p.expires_at-now).total_seconds())
        if changed:
            self.retry_at = monotonic_now
        self.tick(monotonic_now=monotonic_now)

    def stop(self, state: str = 'stopped') -> None:
        self.children.stop()
        self.deadline = 0
        self.state = state

    def tick(self, *, monotonic_now: float) -> None:
        if not self.policy or not self.policy.enabled or not self.deadline:
            return
        if monotonic_now >= self.deadline:
            self.stop('expired')
            return
        if self.children.alive():
            self.state = 'tunnel_connected' if getattr(self.children,'connected',lambda:False)() else 'connecting'
            self.failures = 0
        elif monotonic_now >= self.retry_at:
            self.children.stop()
            try:
                self.children.start(self.policy)
            except Exception:
                self.children.stop()
                self.state = 'process_failed'
            else:
                self.state = 'connecting'
            self.failures += 1
            self.retry_at = monotonic_now + min(60, 2 ** min(self.failures, 6))



class SupportHTTPError(RuntimeError):
    def __init__(self, status: int, *, reset_device_id: str | None = None):
        self.status = status
        self.reset_device_id = reset_device_id
        super().__init__('support_http_error')


def validate_origin(origin: str):
    from urllib.parse import urlsplit
    import ipaddress
    parsed = urlsplit(origin)
    host = parsed.hostname or ''
    if (parsed.scheme != 'https' or parsed.username or parsed.password or
            parsed.path not in ('', '/') or parsed.query or parsed.fragment or
            not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,251}[A-Za-z0-9]', host) or '.' not in host):
        raise ValueError('invalid_support_origin')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host, parsed.port or 443
    raise ValueError('invalid_support_origin')


class SupportHTTPClient:
    """Pinned-CA HTTPS, no redirects/proxy discovery, bounded response and timeout."""
    def __init__(self, origin: str, ca_file: Path, token: str, *, bootstrap: bool = False):
        self.host, self.port = validate_origin(origin)
        self.ca_file = ca_file
        pattern = r'[A-Za-z0-9_-]{43}' if bootstrap else r'eps1\.[0-9a-f]{32}\.[0-9a-f]{64}'
        if not isinstance(token, str) or not re.fullmatch(pattern, token):
            raise ValueError('invalid_support_credential')
        self._token = token
        self._bootstrap = bootstrap

    def request(self, suffix: str, body=None):
        import http.client
        import json
        import ssl
        if suffix not in {'register', 'policy', 'status', 'unregister'}:
            raise ValueError('invalid_support_operation')
        if self._bootstrap != (suffix == 'register'):
            raise ValueError('invalid_support_authority')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_verify_locations(cafile=str(self.ca_file))
        connection = http.client.HTTPSConnection(self.host, self.port, context=context, timeout=8)
        try:
            encoded = json.dumps(body).encode() if body is not None else None
            connection.request('POST' if encoded is not None else 'GET',
                '/agent/v1/support-access/'+suffix, body=encoded,
                headers={'Authorization': 'Bearer '+self._token, 'Content-Type':'application/json'})
            response = connection.getresponse()
            raw = response.read(65537)
            if suffix == 'unregister' and response.status == 204:
                return {}
            if response.status != 200:
                marker=None
                if self._bootstrap and suffix=='register' and response.status==409:
                    value=response.getheader('X-Support-Reset-Device')
                    try:
                        if str(uuid.UUID(value))==value:marker=value
                    except (ValueError,TypeError,AttributeError):
                        pass
                raise SupportHTTPError(response.status,reset_device_id=marker)
            if len(raw)>65536:
                raise ValueError('invalid_support_response')
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError('invalid_support_response')
            return value
        finally:
            connection.close()

    def register(self, body):
        return self.request('register', body)

    def policy(self):
        return self.request('policy')

    def unregister(self):
        return self.request('unregister', {})

    def status(self, *, connected: bool, error: str | None):
        return self.request('status', dict(installed=True, tunnel_connected=connected,last_error_code=error,
            component_version=COMPONENT_VERSION))


def install_support_access(data_root: Path, install_root: Path, *, origin: str,
                           ca_pem: str, device_id: str, device_token: str,
                           service_executable: Path, _ops=None, _client=None) -> dict:
    """Installer-only hook after durable enrollment; never retain device_token.

    The caller authenticates the signed component as part of its native payload.
    Support roots are siblings of Agent so LocalService cannot replace them.
    Existing private keys are retained on retry/upgrade. Registration is idempotent.
    """
    import json
    from .support_access_native import WindowsSupportOps, atomic_write
    if str(uuid.UUID(device_id)) != device_id:
        raise ValueError('invalid_support_identity')
    validate_origin(origin)
    ops = _ops or WindowsSupportOps()
    root = Path(data_root).parent/'Support'
    program = Path(install_root).parent/'Support'
    ops.protect(root)
    ops.protect(program)
    target = program/'EndpointSupportAccess.exe'
    with ops.prepare_payload(service_executable,target) as activation:
        config_path = root/'support.json'
        current=None
        if config_path.exists():
            current = json.loads(config_path.read_text(encoding='utf-8'))
            if current.get('device_id') != device_id or current.get('origin') != origin:
                raise ValueError('support_identity_conflict')
        activation.snapshot_configuration(config_path)
        dependencies = ops.dependencies(previous=current.get('dependencies') if current else None,
            existing=activation.old is not None or activation.state is not None)
        tunnel_key = public_key(ops.key(root, 'tunnel_ed25519'))
        host_key = public_key(ops.key(root, 'host_ed25519'))
        if tunnel_key == host_key:
            raise ValueError('support_key_role_conflict')
        atomic_write(root/'ca.pem', ca_pem)
        ops.protect(root/'ca.pem')
        client = _client or SupportHTTPClient(origin, root/'ca.pem', device_token, bootstrap=True)
        def register():
            return client.register(dict(tunnel_public_key=tunnel_key,host_public_key=host_key,component_version=COMPONENT_VERSION))
        try:
            result=register()
        except SupportHTTPError as error:
            if error.status!=409 or error.reset_device_id!=device_id:
                raise
            # Only an explicit authenticated central reset grant permits rotation.
            # Never restore revoked keys if the second registration reply is lost.
            activation.stop()
            activation.invalidate_configuration_compensation()
            ops.rotate_keys(root)
            tunnel_key=public_key(ops.key(root,'tunnel_ed25519'))
            host_key=public_key(ops.key(root,'host_ed25519'))
            if tunnel_key==host_key:raise ValueError('support_key_role_conflict')
            result=register() # Exactly one retry; new keys remain durable on failure.
        if result.get('device_id') != device_id or not re.fullmatch(r'eps1\.[0-9a-f]{32}\.[0-9a-f]{64}', result.get('support_token','')):
            raise ValueError('invalid_support_registration')
        credential_id = str(uuid.UUID(result['credential_id']))
        if str(uuid.UUID(result['support_token'].split('.')[1])) != credential_id:
            raise ValueError('invalid_support_registration')
        atomic_write(root/'credential', result['support_token'])
        ops.protect(root/'credential')
        # No active lease is cached: every service boot requires fresh HTTPS policy.
        atomic_write(config_path, json.dumps(dict(device_id=device_id,origin=origin,
            credential_id=credential_id,component_version=COMPONENT_VERSION,dependencies=dependencies)))
        ops.protect(config_path)
        activation.require_initialized_readiness()
        activation.apply(reload=True)
        return dict(installed=True,component_version=COMPONENT_VERSION,device_id=device_id)


def uninstall_support_access(*, _ops=None, _client=None) -> dict:
    """Revoke owned authority, stop the owned service and erase only owned data.

    The staged signed helper removes the independently owned active image.
    Transport failure is explicit; local shutdown/removal still fails closed.
    Historical authorization/access audit remains on the server.
    """
    import json
    from .support_access_native import WindowsSupportOps, assert_private, production_roots
    root,program = production_roots()
    ops = _ops or WindowsSupportOps()
    with ops.activation_lock():
        revoked = False
        if root.exists():
            assert_private(root)
            servicing=root/'os-servicing.json'
            if servicing.exists():
                assert_private(servicing)
                if servicing.stat().st_size>8192:
                    raise RuntimeError('support_dependency_recovery_required')
                record=json.loads(servicing.read_bytes())
                if (not isinstance(record,dict) or record.get('schema_version') not in (1,2)
                        or record.get('state') not in {'complete','failed','reboot_required','conflict','installed_unverified'}):
                    raise RuntimeError('support_dependency_recovery_required')
                if record['schema_version']==2:
                    from .support_access_os import WindowsFOD
                    # Never erase state underneath an orphan still finishing.
                    WindowsFOD(root).completed_operation(record)
            try:
                if _client is None:
                    for name in ('support.json','credential','ca.pem'):
                        assert_private(root/name)
                    config = json.loads((root/'support.json').read_text(encoding='utf-8'))
                    _client = SupportHTTPClient(config['origin'],root/'ca.pem',(root/'credential').read_text().strip())
                _client.unregister()
                revoked = True
            except SupportHTTPError as error:
                revoked = error.status in {401,403,404,410}
            except Exception:
                pass
        ops.remove_service()
        ops.remove_runtime()
        for name in ('credential','support.json','ca.pem','host_ed25519','host_ed25519.pub',
                     'tunnel_ed25519','tunnel_ed25519.pub','authorized_keys','known_hosts','sshd_config','sshd.pid','tunnel.log',
                     'os-servicing.json','readiness-request.json','readiness.json'):
            path = root/name
            if path.exists():
                assert_private(path)
                path.unlink()
        if root.exists():
            try:
                root.rmdir()
            except OSError:
                pass
        return dict(installed=False,revoked=revoked,payload_removal_required=ops.remove_payload(program))
