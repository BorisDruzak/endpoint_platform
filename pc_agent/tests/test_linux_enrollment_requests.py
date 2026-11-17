"""Native-client enrollment survives lost response without another identity."""
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from tests.contracts.test_linux_support_lifecycle import native_data


class PrivateStore:
    """Coordinator private-store boundary; copies emulate process restarts."""
    def __init__(self):
        self.value = None
    def read(self):
        import copy
        return copy.deepcopy(self.value)
    def write(self, value):
        import copy
        self.value = copy.deepcopy(value)


def test_native_transport_configuration_does_not_import_core_runtime():
    import subprocess
    import sys
    program = '''
import importlib.abc,sys
class NoCore(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname.startswith('pc_agent.core'):
            raise AssertionError('Native enrollment depends on Core')
sys.meta_path.insert(0,NoCore())
import pc_agent.platform.linux.enrollment_requests as module
module.ssl.create_default_context=lambda **kwargs: object()
module.LinuxEnrollmentHttpsTransport('https://endpoint.sosnadmin.local','fixture-ca')
'''
    result=subprocess.run([sys.executable,'-c',program],capture_output=True,text=True)
    assert result.returncode==0,result.stderr


@pytest.mark.asyncio
async def test_lost_exchange_reuses_durable_claim_nonce_and_timestamp():
    from pc_agent.platform.linux.enrollment_requests import LinuxEnrollmentClient, EnrollmentPending
    from endpoint_contracts.linux_enrollment import LinuxPreEnrollmentRequestCreateV1
    from endpoint_contracts.linux_installation_lifecycle import LinuxNativeSource
    private = PrivateStore()
    source = LinuxNativeSource(**{k:v for k,v in native_data().items() if k!='exit_code'})
    request = LinuxPreEnrollmentRequestCreateV1(schema_version='linux_pre_enrollment_request_create_v1', platform='linux',
        installation_id='linux-native-fixture', hardware_fingerprint='sha256:hardware-fixture', request_capability='a'*43,
        native=source, requested_at=datetime.now(UTC), hostname='fixture')
    exchanges = []
    device_id = str(uuid4())
    request_id = str(uuid4())
    class Transport:
        async def post(self, path, payload, *, bearer=None):
            if path == '/api/v1/enrollment/linux/requests':
                return dict(schema_version='pre_enrollment_request_status_v1', request_id=request_id,
                    status='auto_approved', expires_at=(datetime.now(UTC)+timedelta(hours=1)).isoformat())
            if path.endswith('/claim'):
                return dict(claim='ic_fixture-claim',expires_at=(datetime.now(UTC)+timedelta(minutes=15)).isoformat())
            assert path == '/agent/v1/enroll'
            exchanges.append((payload, bearer))
            if len(exchanges) == 1:
                raise TimeoutError('response lost')
            return dict(schema_version='agent_enrollment_delivery_v1', device_id=device_id,
                policy_id='linux-test', policy={}, enrollment_receipt='c'*43,device_token='d'*43,
                issued_at=request.requested_at.isoformat())
    client = LinuxEnrollmentClient(private, Transport())
    with pytest.raises(EnrollmentPending):
        await client.advance(request, retained_identity=False)
    assert private.value is not None
    client = LinuxEnrollmentClient(private, Transport())
    result = await client.advance(request, retained_identity=False)
    assert str(result.device_id) == device_id
    assert exchanges[0] == exchanges[1]
    assert private.value['delivery']['device_token'] == 'd'*43
    assert 'fixture-claim' not in repr(client)
    # A completed private delivery survives a further restart without network.
    assert (await LinuxEnrollmentClient(private, Transport()).advance(request, retained_identity=False)).device_id == result.device_id
    assert len(exchanges) == 2


@pytest.mark.asyncio
async def test_retained_identity_does_not_read_request_or_consume_claim():
    from pc_agent.platform.linux.enrollment_requests import LinuxEnrollmentClient
    class Forbidden:
        def read(self):
            raise AssertionError('retained identity touched fresh state')
        async def post(self,*args,**kwargs):
            raise AssertionError('retained identity attempted enrollment')
    assert await LinuxEnrollmentClient(Forbidden(), Forbidden()).advance(None, retained_identity=True) is None


@pytest.mark.asyncio
async def test_missing_campaign_preserves_attempt_and_requires_explicit_recovery():
    from pc_agent.platform.linux.enrollment_requests import LinuxEnrollmentClient, EnrollmentPending
    from endpoint_contracts.linux_enrollment import LinuxPreEnrollmentRequestCreateV1
    private = PrivateStore()
    request = LinuxPreEnrollmentRequestCreateV1(schema_version='linux_pre_enrollment_request_create_v1',platform='linux',
        installation_id='missing-authority',hardware_fingerprint='sha256:hardware-fixture',request_capability='a'*43,
        native={k:v for k,v in native_data().items() if k!='exit_code'},requested_at=datetime.now(UTC),hostname='fixture')
    calls=[]
    request_id=str(uuid4())
    class Transport:
        async def post(self,path,payload,**kwargs):
            calls.append(path)
            assert path == '/api/v1/enrollment/linux/requests' or path.endswith('/status')
            return dict(schema_version='pre_enrollment_request_status_v1',request_id=request_id,
                status='review_required',reason='NO_MATCHING_CAMPAIGN',expires_at=(datetime.now(UTC)+timedelta(hours=1)).isoformat())
    for _ in range(2):
        with pytest.raises(EnrollmentPending,match='Linux campaign authority unresolved; explicit recovery required'):
            await LinuxEnrollmentClient(private,Transport()).advance(request,retained_identity=False)
    assert calls.count('/api/v1/enrollment/linux/requests') == 1
    assert private.value['request_id'] == request_id and private.value['claim'] is None
