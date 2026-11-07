"""Native coordinator enrollment, independent of Core, WSS and user sessions.

The coordinator supplies an exclusively owned private store. This is a protected
credential store, NEVER the lifecycle outbox/receipt or ordinary command args.
Every uncertain exchange retains its exact claim/nonce/time and received result.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import secrets
import ssl
import stat

import aiohttp
from endpoint_contracts.enrollment import AgentEnrollmentDeliveryV1, AgentEnrollmentRequestV1, PreEnrollmentRequestStatusV1
from endpoint_contracts.linux_enrollment import LinuxPreEnrollmentRequestCreateV1
from pc_agent.enrollment_bootstrap import _atomic_secret_write, _require_safe_path_components


class EnrollmentPending(RuntimeError):
    """Bounded public outcome; private attempt must be retained for recovery."""


class LinuxPrivateEnrollmentStore:
    """Root-owned0600 credential store inside an existing root-only directory.

    Native Linux only. The caller must hold locked() throughout advance and
    permanent identity persistence. No implicit directory creation or cleanup.
    """
    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.path = self.directory / 'fresh-enrollment-private.json'
        self._locked = False

    def _validate_directory(self):
        if os.name != 'posix' or os.geteuid() != 0:
            raise EnrollmentPending('Native root enrollment store required')
        _require_safe_path_components(self.directory, include_leaf=True)
        for parent in (self.directory, *self.directory.parents):
            info = parent.lstat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise EnrollmentPending('Unsafe enrollment store ownership')
        if stat.S_IMODE(self.directory.stat().st_mode) != 0o700:
            raise EnrollmentPending('Private enrollment directory required')

    @contextmanager
    def locked(self):
        self._validate_directory()
        import fcntl
        fd = os.open(self.directory / '.enrollment.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
                raise EnrollmentPending('Unsafe enrollment lock')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._locked = True
            yield self
        finally:
            self._locked = False
            os.close(fd)

    def read(self):
        if not self._locked:
            raise EnrollmentPending('Exclusive enrollment ownership required')
        self._validate_directory()
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 65536):
                raise EnrollmentPending('Unsafe enrollment credential state')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                return json.loads(stream.read(65537))
        finally:
            os.close(fd)

    def write(self, value):
        if not self._locked:
            raise EnrollmentPending('Exclusive enrollment ownership required')
        self.read()  # Validate any retained node before atomic replacement.
        raw = json.dumps(value, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')
        if len(raw) > 65536:
            raise EnrollmentPending('Enrollment credential state exceeds bound')
        _atomic_secret_write(self.path, raw, uid=0, gid=0)


class LinuxEnrollmentHttpsTransport:
    """Strict configured origin/CA, no redirect or environment proxy authority."""
    def __init__(self, endpoint_url: str, ca_file: Path):
        from pc_agent.platform.linux.enrollment_origin import configured_endpoint_origin
        if endpoint_url != configured_endpoint_origin():
            raise ValueError('Explicit configured Endpoint origin required')
        self.origin = endpoint_url
        self.ssl = ssl.create_default_context(cafile=str(ca_file))

    async def post(self, path, payload, *, bearer=None):
        headers = {} if bearer is None else {'Authorization': 'Bearer ' + bearer}
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15), trust_env=False) as session:
                async with session.post(self.origin + path, json=payload, headers=headers,
                    ssl=self.ssl, allow_redirects=False) as response:
                    if response.status not in (200, 201):
                        raise EnrollmentPending('Enrollment requires review or retry')
                    data = bytearray()
                    async for chunk in response.content.iter_chunked(4096):
                        data.extend(chunk)
                        if len(data) > 65536:
                            raise EnrollmentPending('Enrollment response exceeds bound')
                    return json.loads(data)
        except Exception:
            raise EnrollmentPending('Enrollment response unavailable; retain private attempt') from None


class LinuxEnrollmentClient:
    """One bounded step. Reuse the same store on restart; never reset on errors."""
    def __init__(self, private_store, transport):
        self._store = private_store
        self._transport = transport

    async def advance(self, request: LinuxPreEnrollmentRequestCreateV1 | None, *, retained_identity: bool):
        # A verified retained identity is outside fresh enrollment entirely.
        if retained_identity:
            return None
        try:
            state = self._store.read()
            if state is None:
                if not isinstance(request, LinuxPreEnrollmentRequestCreateV1):
                    raise EnrollmentPending('Fresh native request required')
                state = {'request': request.model_dump(mode='json'), 'nonce': secrets.token_urlsafe(32),
                    'request_id': None, 'status': None, 'claim': None, 'delivery': None}
                self._store.write(state)
            frozen = LinuxPreEnrollmentRequestCreateV1.model_validate(state['request'])
            if request is not None and request != frozen:
                raise EnrollmentPending('Retained enrollment attempt differs; preserve ownership')
            if state['delivery'] is not None:
                return AgentEnrollmentDeliveryV1.model_validate(state['delivery'])
            if state['request_id'] is None:
                status = PreEnrollmentRequestStatusV1.model_validate(await self._transport.post(
                    '/api/v1/enrollment/linux/requests', frozen.model_dump(mode='json')))
                state['request_id'], state['status'] = str(status.request_id), status.status
                self._store.write(state)
            from uuid import UUID
            request_id = str(UUID(state['request_id']))
            prefix = '/api/v1/enrollment/linux/requests/' + request_id
            if state['claim'] is None:
                if state['status'] not in ('auto_approved', 'approved', 'claim_issued'):
                    status = PreEnrollmentRequestStatusV1.model_validate(await self._transport.post(
                        prefix + '/status', {'request_capability': frozen.request_capability}))
                    if str(status.request_id) != request_id:
                        raise EnrollmentPending('Enrollment status identity differs')
                    state['status'] = status.status
                    self._store.write(state)
                    if status.reason in ('NO_MATCHING_CAMPAIGN', 'AMBIGUOUS_CAMPAIGN'):
                        raise EnrollmentPending('Linux campaign authority unresolved; explicit recovery required')
                    if status.status not in ('auto_approved', 'approved', 'claim_issued'):
                        raise EnrollmentPending('Enrollment awaits approval or explicit recovery')
                response = await self._transport.post(prefix + '/claim', {
                    'request_capability': frozen.request_capability, 'installation_id': frozen.installation_id,
                    'hardware_fingerprint': frozen.hardware_fingerprint})
                claim = response['claim']
                if not isinstance(claim, str) or not claim.startswith('ic_') or not 4 <= len(claim) <= 512 or not claim.isascii() or any(c.isspace() for c in claim):
                    raise EnrollmentPending('Invalid claim response; retain request')
                state['claim'] = claim
                self._store.write(state)  # MUST precede any consuming exchange.
            enrollment = AgentEnrollmentRequestV1(schema_version='agent_enrollment_request_v1', platform='linux',
                installation_id=frozen.installation_id, hardware_fingerprint=frozen.hardware_fingerprint,
                delivery_nonce=state['nonce'], requested_at=frozen.requested_at)
            delivery = AgentEnrollmentDeliveryV1.model_validate(await self._transport.post('/agent/v1/enroll',
                enrollment.model_dump(mode='json'), bearer=state['claim']))
            state['delivery'] = delivery.model_dump(mode='json')
            self._store.write(state)  # Permanent result survives before Core starts.
            return delivery
        except EnrollmentPending:
            raise
        except Exception:
            raise EnrollmentPending('Enrollment uncertain; retain private attempt') from None
