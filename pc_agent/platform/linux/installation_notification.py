"""Bounded post-owner HTTPS delivery and original installed bootstrap only."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import stat

import aiohttp
import yaml

from endpoint_contracts.installation_lifecycle import InstallationEventAckV1
from endpoint_contracts.linux_enrollment import LinuxPreEnrollmentRequestCreateV1
from pc_agent.enrollment_identity import serialize_enrollment_identity, canonical_enrollment_device_id
from pc_agent.platform.linux.enrollment_origin import configured_endpoint_origin
from pc_agent.platform.linux.enrollment_requests import LinuxPrivateEnrollmentStore, LinuxEnrollmentClient
from pc_agent.platform.linux.installation_lifecycle import LifecycleJournal, InstallationPending

DATA = Path('/var/lib/endpoint-agent')
CONFIG = Path('/etc/endpoint-agent/config.yaml')
CA = Path('/etc/endpoint-agent/ca.crt')


def read_secret(path, *, uid=0, gid=0, missing=False):
    path = Path(path)
    for parent in path.parents:
        info = parent.lstat()
        allowed = (uid, gid) if parent == DATA else (0, 0)
        if (not stat.S_ISDIR(info.st_mode) or (info.st_uid, info.st_gid) != allowed
            or info.st_mode & 0o022):
            raise InstallationPending('unsafe_secret_parent')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        if missing:
            return None
        raise InstallationPending('required_secret_absent') from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or (info.st_uid, info.st_gid) != (uid, gid)
            or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 65536):
            raise InstallationPending('unsafe_canonical_secret')
        return os.read(fd, 65537)
    finally:
        os.close(fd)


def canonical_identity():
    import pwd
    try:
        account = pwd.getpwnam('endpoint-agent')
    except KeyError:
        return None, None
    if not DATA.exists() and not DATA.is_symlink():
        return None, None
    credential = read_secret(DATA/'device-credential', uid=account.pw_uid, gid=account.pw_gid, missing=True)
    identity = read_secret(DATA/'enrollment-identity.json', uid=account.pw_uid, gid=account.pw_gid, missing=True)
    if credential is None and identity is None:
        return None, None
    if credential is None or identity is None:
        raise InstallationPending('partial_canonical_identity_requires_recovery')
    value = json.loads(identity)
    device = str(canonical_enrollment_device_id(value.get('device_id')))
    if identity != serialize_enrollment_identity(device):
        raise InstallationPending('canonical_identity_schema')
    token = credential.decode('ascii').rstrip('\r\n')
    if not re.fullmatch('[A-Za-z0-9_-]{43}', token) or credential not in (token.encode(), (token+'\n').encode(), (token+'\r\n').encode()):
        raise InstallationPending('canonical_credential_schema')
    return device, token


class NotificationTransport:
    def __init__(self, origin, ca):
        if origin != configured_endpoint_origin():
            raise InstallationPending('configured_origin_required')
        self.origin, self.ssl = origin, ssl.create_default_context(cadata=ca.decode('ascii'))

    async def post(self, path, payload, bearer=None):
        headers = {'Authorization': 'Bearer ' + bearer} if bearer else {}
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15), trust_env=False) as session:
                async with session.post(self.origin + path, json=payload, headers=headers,
                    ssl=self.ssl, allow_redirects=False) as response:
                    if response.status == 204:
                        return None
                    if response.status not in (200, 201):
                        raise InstallationPending('notification_pending')
                    raw = bytearray()
                    async for chunk in response.content.iter_chunked(4096):
                        raw.extend(chunk)
                        if len(raw) > 65536:
                            raise InstallationPending('response_bound')
                    return json.loads(raw)
        except Exception:
            raise InstallationPending('notification_pending') from None


async def drain_events(journal, transport, credential):
    for event in journal.pending_events():
        ack = InstallationEventAckV1.model_validate(await transport.post(
            '/agent/v1/installation/linux/events', event, bearer=credential))
        if ack.state != event['action']:
            raise InstallationPending('native_ack_state_mismatch')
        journal.acknowledge(ack.model_dump(mode='json'))


def report_support_unavailable():
    """Known rollback has no Support code; retain token/keys and original lease."""
    from pc_agent.platform.linux.support_access_native import PrivateStore, SupportPaths
    from pc_agent.platform.linux.support_access_service import SupportHTTPS, validate_config, bounded_request
    paths = SupportPaths()
    if not paths.private.exists():
        return
    store = PrivateStore(paths)
    with store.locked():
        raw = store.json('config.json', missing=True)
        if raw is None:
            return
        config = validate_config(raw)
        client = SupportHTTPS(config['origin'], paths.private/'ca.crt')
        bounded_request(lambda: client.request('status', config['support_token'],
            {'platform':'linux_amd64','component_version':'1.0.0','installed':False,
             'tunnel_connected':False,'last_error_code':'service_failed'}))


def _activate_delivery(delivery):
    """Recoverable two-file activation; Core stays stopped until exact pair reads."""
    import pwd
    from pc_agent.enrollment_bootstrap import _atomic_secret_write
    account = pwd.getpwnam('endpoint-agent')
    expected = {'device-credential': delivery.device_token.encode('ascii'),
        'enrollment-identity.json': serialize_enrollment_identity(delivery.device_id)}
    if not re.fullmatch(rb'[A-Za-z0-9_-]{43}', expected['device-credential']):
        raise InstallationPending('invalid_delivered_credential')
    # Validate the COMPLETE retained pair before writing either missing member.
    for name, raw in expected.items():
        prior = read_secret(DATA/name, uid=account.pw_uid, gid=account.pw_gid, missing=True)
        if prior is not None and prior != raw:
            raise InstallationPending('delivered_identity_conflict')
    for name, raw in expected.items():
        if read_secret(DATA/name, uid=account.pw_uid, gid=account.pw_gid, missing=True) is None:
            _atomic_secret_write(DATA/name, raw, uid=account.pw_uid, gid=account.pw_gid)
    if canonical_identity() != (str(delivery.device_id), delivery.device_token):
        raise InstallationPending('canonical_activation_incomplete')


async def ensure_identity(store, operation, transport, config):
    private = LinuxPrivateEnrollmentStore(store.paths.private)
    with private.locked():
        pending = private.read()
        if pending is not None and pending.get('delivery') is not None and not pending.get('canonical_acknowledged'):
            # A partial pair may only be completed from the SAME durable delivery.
            from endpoint_contracts.enrollment import AgentEnrollmentDeliveryV1
            delivery = AgentEnrollmentDeliveryV1.model_validate(pending['delivery'])
            _activate_delivery(delivery)
        device, token = canonical_identity()
        if device is not None:
            if pending is not None and pending.get('delivery') is not None and not pending.get('canonical_acknowledged'):
                delivery = pending['delivery']
                await transport.post('/agent/v1/enroll/ack', {'schema_version': 'enrollment_delivery_proof_v1',
                    'enrollment_receipt': delivery['enrollment_receipt'],
                    'hardware_fingerprint': pending['request']['hardware_fingerprint']}, bearer=token)
                pending['canonical_acknowledged'] = True
                private.write(pending)
            return device, token
        if operation['action'] == 'remove':
            raise InstallationPending('removal_identity_absent')
        request = None
        if pending is None:
            from pc_agent.core.device_fingerprint import collect_device_fingerprint
            from pc_agent.enrollment_bootstrap import _derive_hardware_fingerprint
            request = LinuxPreEnrollmentRequestCreateV1(schema_version='linux_pre_enrollment_request_create_v1',
                platform='linux', installation_id=config['provisioning']['installation_id'],
                hardware_fingerprint=_derive_hardware_fingerprint(collect_device_fingerprint),
                request_capability=secrets.token_urlsafe(32), requested_at=datetime.now(timezone.utc),
                hostname=socket.gethostname(), native=operation['source'])
        delivery = await LinuxEnrollmentClient(private, transport).advance(request, retained_identity=False)
        _activate_delivery(delivery)
        pending = private.read()
        await transport.post('/agent/v1/enroll/ack', {'schema_version':'enrollment_delivery_proof_v1',
            'enrollment_receipt': delivery.enrollment_receipt,
            'hardware_fingerprint':pending['request']['hardware_fingerprint']}, bearer=delivery.device_token)
        pending['canonical_acknowledged'] = True
        private.write(pending)
        return str(delivery.device_id), delivery.device_token


async def notify(store):
    """Called only after native owner exits; bounded120s caller, no native replay."""
    from pc_agent.platform.linux.installation_coordinator import RPMBackend, NativeCoordinator
    from pc_agent.platform.linux.support_access_service import install_from_enrollment
    with store.locked():
        journal, backend = LifecycleJournal(store), RPMBackend(store)
        operation = journal.state()['operation']
        if not operation or operation.get('bootstrap') == 'complete':
            return
        if operation.get('unmanaged') or type(operation.get('exit_code')) is not int or operation['exit_code'] != 0:
            raise InstallationPending('no_known_native_bootstrap')
        if not backend.matches(operation['action'], operation['source']):
            raise InstallationPending('bootstrap_native_source_changed')
        config = yaml.safe_load(read_secret(CONFIG))
        ca = read_secret(CA)
        gateway = config['gateway']
        if gateway['ca_file'] != str(CA) or gateway['endpoint'] != configured_endpoint_origin():
            raise InstallationPending('canonical_configuration_conflict')
        transport = NotificationTransport(gateway['endpoint'], ca)
        device, credential = await ensure_identity(store, operation, transport, config)
        NativeCoordinator(journal, backend).reconcile(device_id=device)
        await drain_events(journal, transport, credential)
        if operation['action'] == 'remove':
            return
        if operation['source']['version'] == '3.2.156':
            # Historical rollback has no independent Support; preserve private keys.
            report_support_unavailable()
            journal.complete_bootstrap()
            backend._systemctl('start', 'endpoint-agent.service', 'endpoint-agent-update.path')
            return
        # Only the original genuinely pending native bootstrap can register.
        journal.request_bootstrap()
        backend._systemctl('stop', 'endpoint-support-access.service')
        install_from_enrollment(device_id=device, credential_reader=lambda: credential,
            endpoint_origin=gateway['endpoint'], ca_bytes=ca,
            register_retained=journal.state()['operation'].get('registration') != 'complete')
        journal.registration_complete()
        backend._systemctl('enable', '--now', 'endpoint-support-access.service')
        # Installation completion only, never an ongoing Support-health/lease
        # dependency. Disabled registration policy is still successful bootstrap.
        store.write('runtime-ready', json.dumps({'operation_id':operation['id'],
            'source_revision':operation['source']['source_revision']}).encode())
        backend._systemctl('start', 'endpoint-agent.service', 'endpoint-agent-update.path')
        if operation['source']['user_sensor_nevra']:
            backend._systemctl('start', 'endpoint-agent-browser-policy.service')
            from pc_agent.platform.linux.installation_user_sessions import handoff_active_sensors
            handoff = handoff_active_sensors(store=store)
            store.write('sensor-handoff-result.json', json.dumps(handoff).encode())
        # Terminal before timer stop: a crash cannot authorize re-registration.
        journal.complete_bootstrap()
        backend._systemctl('disable', '--now', 'endpoint-agent-setup-retry.timer')
