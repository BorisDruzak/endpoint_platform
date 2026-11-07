"""Independent Linux Support1.0.0 policy; no Core, updater or WSS dependency."""
from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from uuid import UUID

COMPONENT_VERSION = '1.0.0'
SERVICE_NAME = 'endpoint-support-access.service'
ORIGINS = {'https://endpoint.sosnadmin.local': 'endpoint.sosnadmin.local',
           'https://endpoint-staging.sosnadmin.local': 'endpoint-staging.sosnadmin.local'}
LOCAL_PORT = 22222
MAX_LEASE = 8 * 3600


class SupportError(RuntimeError):
    """Only fixed, bounded codes cross the native/operator boundary."""


def public_key(value):
    try:
        if not isinstance(value, str) or not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]+={0,2}', value):
            raise ValueError
        blob = base64.b64decode(value.split()[1], validate=True)
        if (len(blob) != 51 or blob[:19] != b'\0\0\0\x0bssh-ed25519\0\0\0 '
                or base64.b64encode(blob).decode() != value.split()[1]):
            raise ValueError
        return value
    except (ValueError, TypeError):
        raise SupportError('invalid_key') from None


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise SupportError('invalid_policy')
    return value


def safe_path(path):
    value = str(path)
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+', value) or '..' in Path(value).parts:
        raise SupportError('unsafe_path')
    return value


@dataclass(frozen=True)
class SupportPolicy:
    device_id: str
    enabled: bool
    revision: int
    expires_at: float | None = None
    gateway: str = ''
    gateway_key: str = ''
    tunnel_user: str = ''
    remote_port: int = 0
    username: str | None = None
    uid: int | None = None
    operator_keys: tuple[str, ...] = ()

    @classmethod
    def parse(cls, raw, *, device_id, origin, host_key, tunnel_key):
        try:
            fields = {'platform','device_id','enabled','revision','expires_at','gateway_host',
                'gateway_port','gateway_host_public_key','tunnel_user','remote_port','local_port',
                'linux_admin_username','linux_admin_uid','operator_public_keys','poll_after_seconds'}
            if (not isinstance(raw, dict) or set(raw)-fields or raw['platform'] != 'linux_amd64'
                or str(UUID(device_id)) != device_id or raw['device_id'] != device_id
                or type(raw['enabled']) is not bool or origin not in ORIGINS):
                raise ValueError
            revision = integer(raw['revision'], 0, 2**63-1)
            if not raw['enabled']:
                if any(raw.get(k) is not None for k in ('expires_at','linux_admin_username','linux_admin_uid')) or raw.get('operator_public_keys') != []:
                    raise ValueError
                return cls(device_id, False, revision)
            expiry = datetime.fromisoformat(raw['expires_at'].replace('Z','+00:00'))
            if expiry.tzinfo is None or raw['gateway_host'] != ORIGINS[origin]:
                raise ValueError
            integer(raw['gateway_port'], 2222, 2222)
            integer(raw.get('local_port', LOCAL_PORT), LOCAL_PORT, LOCAL_PORT)
            integer(raw.get('poll_after_seconds',30), 30, 30)
            user = 'eps-' + UUID(device_id).hex[:24]
            if raw['tunnel_user'] != user or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', raw['linux_admin_username']):
                raise ValueError
            uid = integer(raw['linux_admin_uid'], 0, 2147483647)
            keys = raw['operator_public_keys']
            if not isinstance(keys,list) or not 1 <= len(keys) <= 16:
                raise ValueError
            keys = tuple(public_key(k) for k in keys)
            roles = [public_key(host_key),public_key(tunnel_key),public_key(raw['gateway_host_public_key']),*keys]
            if len(set(roles)) != len(roles):
                raise ValueError
            return cls(device_id, True, revision, expiry.timestamp(), raw['gateway_host'],
                roles[2], user, integer(raw['remote_port'],32000,41999), raw['linux_admin_username'],uid,keys)
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
            raise SupportError('invalid_policy') from None


@dataclass
class LeaseState:
    """Durable original expiry anchor. A fresh HTTPS Date is mandatory after reboot.

    BOOTTIME includes suspend. Repeated reads cannot move an existing deadline;
    only a higher server policy revision may authorize a new expiry.
    """
    revision: int = -1
    fingerprint: str = ''
    boot_id: str = ''
    deadline: float = 0
    authority: dict | None = None
    last_error: str | None = None

    @classmethod
    def from_json(cls, raw):
        try:
            result = cls(**raw)
            integer(result.revision, -1, 2**63-1)
            if not isinstance(result.fingerprint,str) or not isinstance(result.boot_id,str) or not isinstance(result.deadline,(float,int)):
                raise ValueError
            result.authority_policy()
            if result.last_error not in (None,'policy_unavailable','configuration_conflict','key_conflict',
                                         'tunnel_failed','service_failed','dependency_unavailable','host_key_mismatch'):
                raise ValueError
            return result
        except (TypeError,ValueError):
            raise SupportError('invalid_lease_state') from None

    def to_json(self):
        return asdict(self)

    def authority_policy(self):
        """Public last-enabled consent, for local readiness only, never admission."""
        if self.authority is None:
            return None
        try:
            policy = SupportPolicy(**self.authority)
            if (not policy.enabled or policy.revision != self.revision or
                hashlib.sha256(json.dumps(asdict(policy),sort_keys=True).encode()).hexdigest() != self.fingerprint):
                raise ValueError
            return policy
        except (TypeError, ValueError):
            raise SupportError('invalid_lease_state') from None

    def accept(self, policy, *, wall, server, boot, boot_id):
        fingerprint = hashlib.sha256(json.dumps(asdict(policy),sort_keys=True).encode()).hexdigest()
        if policy.revision < self.revision:
            raise SupportError('stale_policy')
        if not policy.enabled:
            if policy.revision > self.revision:
                self.revision,self.fingerprint,self.boot_id,self.deadline,self.authority = policy.revision,'','',0,None
            elif self.fingerprint == fingerprint:
                # Compatibility with a pre-fix state that bound only a masked
                # disabled projection. It contains no administrator authority.
                self.fingerprint = ''
            # Keep a previously bound enabled fingerprint and BOOTTIME anchor.
            # Disabled is an effective mask, not replacement administrator consent.
            return 0
        if policy.revision == self.revision and self.fingerprint and self.fingerprint != fingerprint:
            raise SupportError('stale_policy')
        deadline = 0
        if policy.enabled:
            # HTTP Date is authenticated by our pinned-CA TLS origin; local future
            # time shortens authority. Sub-second Date precision never adds time.
            remaining = policy.expires_at - max(wall, server)
            if not 0 < remaining <= MAX_LEASE:
                raise SupportError('expired_policy')
            deadline = boot + remaining
            if policy.revision == self.revision and self.fingerprint and boot_id == self.boot_id:
                deadline = min(deadline,self.deadline)
            if deadline <= boot:
                raise SupportError('expired_policy')
        self.revision,self.fingerprint,self.boot_id,self.deadline = policy.revision,fingerprint,boot_id,deadline
        self.authority = asdict(policy)
        return deadline


class LeaseGate:
    """Network independent expiry; a missing fresh policy closes within60sec."""
    def __init__(self, stop):
        self.stop = stop
        self.deadline = 0

    def arm(self, *, absolute_deadline, boot):
        self.deadline = min(absolute_deadline,boot+60)

    def tick(self, boot):
        if self.deadline and boot < self.deadline:
            return True
        if self.deadline:
            self.deadline = 0
            self.stop()
        return False


def sshd_config(private: Path, public: Path, policy: SupportPolicy, *, port=LOCAL_PORT):
    private,public = safe_path(private),safe_path(public)
    integer(port,1024,65535)
    if not policy.enabled or policy.username is None:
        raise SupportError('disabled_policy')
    return '\n'.join([
        f'Port {port}', 'AddressFamily inet', 'ListenAddress 127.0.0.1',
        f'HostKey {private}/host_ed25519', f'AuthorizedKeysFile {public}/%U',
        'PidFile none', f'AllowUsers {policy.username}',
        'PubkeyAuthentication yes', 'AuthenticationMethods publickey',
        'PasswordAuthentication no', 'KbdInteractiveAuthentication no',
        'PermitRootLogin prohibit-password', 'UsePAM no', 'StrictModes yes',
        'DisableForwarding yes', 'PermitTTY yes', 'PermitUserEnvironment no',
        'PermitUserRC no', 'HostbasedAuthentication no', 'IgnoreRhosts yes',
        'MaxAuthTries 3', 'LoginGraceTime 15', 'MaxSessions 4', 'MaxStartups 3',
        'ClientAliveInterval 15', 'ClientAliveCountMax 2', 'LogLevel ERROR', '',
    ])


def tunnel_command(private: Path, policy: SupportPolicy):
    root = safe_path(private)
    return ['/usr/bin/ssh','-F','/dev/null','-N','-T','-M','-S',root+'/mux',
        '-o','ControlPersist=no','-i',root+'/tunnel_ed25519',
        '-p','2222','-l',policy.tunnel_user,
        '-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes',
        '-o','HostKeyAlias=endpoint-support-gateway','-o',f'UserKnownHostsFile={root}/known_hosts',
        '-o','GlobalKnownHostsFile=/dev/null','-o','ExitOnForwardFailure=yes',
        '-o','ServerAliveInterval=10','-o','ServerAliveCountMax=2','-o','ConnectTimeout=5',
        '-o','ConnectionAttempts=1','-o','ForwardAgent=no','-o','LogLevel=ERROR',policy.gateway]


def forward_command(private: Path, policy: SupportPolicy):
    # Explicit -O requires this existing master; ssh never falls back to a new
    # network connection if the control socket is absent or rejects the request.
    return ['/usr/bin/ssh','-F','/dev/null','-S',safe_path(private)+'/mux',
        '-O','forward','-R',f'127.0.0.1:{policy.remote_port}:127.0.0.1:{LOCAL_PORT}',
        '-o','BatchMode=yes','-o','LogLevel=ERROR',policy.gateway]
