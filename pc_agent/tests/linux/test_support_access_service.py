import json
from threading import Event
import time
import ssl
from contextlib import contextmanager
from pathlib import PurePosixPath
import pytest
from pc_agent.platform.linux import support_access_service as service
from pc_agent.platform.linux.support_access import SupportError


def test_background_policy_io_is_single_flight_and_shutdown_does_not_wait():
    wait = Event()
    worker = service.PolicyWorker(lambda _: wait.wait(20))
    start = time.monotonic()
    assert worker.submit({'installed':True})
    assert not worker.submit({'installed':True})
    assert worker.result() is None
    worker.close()
    assert time.monotonic()-start < 1
    wait.set()


@pytest.mark.parametrize('origin', ['http://endpoint.sosnadmin.local','https://evil.example',
    'https://endpoint.sosnadmin.local/other','https://endpoint.sosnadmin.local:444'])
def test_https_client_rejects_noncanonical_origin_before_connect(origin):
    with pytest.raises(SupportError):
        service.SupportHTTPS(origin,PurePosixPath('/nonexistent'))


def test_http_errors_never_expose_private_response_or_exception():
    def request(_):
        raise ValueError('SECRET credential')
    worker = service.PolicyWorker(request)
    worker.submit({})
    deadline = time.monotonic()+2
    result = None
    while result is None and time.monotonic()<deadline:
        result = worker.result()
        time.sleep(.01)
    worker.close()
    assert result == ('error','https_unavailable')


def test_saved_config_never_accepts_device_token_or_unbound_environment():
    raw = dict(device_id='e46fc348-c48c-415c-a86a-1dd60ef14e1a',credential_id='e46fc348-c48c-415c-a86a-1dd60ef14e1b',
        support_token='eps1.'+'x'*64,origin='https://endpoint.sosnadmin.local',environment='production')
    assert service.validate_config(raw)['support_token'] == raw['support_token']
    for changed in (raw|{'support_token':'device-secret'},raw|{'environment':'staging'},raw|{'device_credential':'secret'}):
        with pytest.raises(SupportError):
            service.validate_config(changed)


@pytest.mark.parametrize('outcome',[None,False,True,21,1,'0'])
def test_unknown_or_failed_native_outcome_cannot_delete_support_identity(outcome):
    with pytest.raises(SupportError):
        service.finalize_removal(known_native_exit_code=outcome)


@pytest.mark.parametrize('status,body,date',[(302,b'private redirect','Sat, 07 Nov 2026 10:00:00 GMT'),
    (200,b'x'*65537,'Sat, 07 Nov 2026 10:00:00 GMT'),(200,b'{}','invalid date')],
    ids=['redirect','oversize','missing-date'])
def test_https_rejects_redirect_oversize_and_missing_authenticated_time(monkeypatch,status,body,date):
    class Response:
        def __init__(self):self.status=status;self.offset=0
        def getheader(self,_name,_default):return date
        def read1(self,count):
            chunk=body[self.offset:self.offset+count];self.offset+=len(chunk);return chunk
    class Connection:
        def __init__(self,*a,**k):pass
        def connect(self):pass
        def request(self,*a,**k):pass
        def getresponse(self):return Response()
        def close(self):pass
    monkeypatch.setattr(service.http.client,'HTTPSConnection',Connection)
    client=object.__new__(service.SupportHTTPS)
    client.host='endpoint.sosnadmin.local';client.ssl=ssl.create_default_context()
    with pytest.raises(SupportError,match='^https_unavailable$'):
        client.request('policy','eps1.private_token')


def test_late_dns_resolution_cannot_send_delayed_mutating_request(monkeypatch):
    sent=[]
    class Connection:
        def __init__(self,*a,**k):pass
        def connect(self):pass
        def request(self,*a,**k):sent.append(True)
        def close(self):pass
    times=iter([0,11])
    monkeypatch.setattr(service.time,'monotonic',lambda:next(times))
    monkeypatch.setattr(service.http.client,'HTTPSConnection',Connection)
    client=object.__new__(service.SupportHTTPS)
    client.host='endpoint.sosnadmin.local';client.ssl=ssl.create_default_context()
    with pytest.raises(SupportError):client.request('unregister','eps1.private_token')
    assert not sent


def test_staging_bootstrap_requires_all_explicit_markers_before_credential_read():
    read=[]
    with pytest.raises(SupportError):
        service.install_from_enrollment(device_id='e46fc348-c48c-415c-a86a-1dd60ef14e1a',
            credential_reader=lambda:read.append(True),endpoint_origin='https://endpoint-staging.sosnadmin.local',
            ca_bytes=b'ca',environment={'ENDPOINT_AGENT_DEPLOYMENT_ENVIRONMENT':'staging'})
    assert not read


def test_second_runtime_cannot_stop_children_owned_by_first(monkeypatch):
    stopped=[]
    class Store:
        def __init__(self,*a):pass
        @contextmanager
        def locked(self):
            raise SupportError('store_busy_or_unsafe')
            yield
    class Children:
        def __init__(self,*a):pass
        def stop(self):stopped.append(True)
    monkeypatch.setattr(service,'PrivateStore',Store)
    monkeypatch.setattr(service,'NativeChildren',Children)
    with pytest.raises(SupportError):service.run_service()
    assert not stopped


def test_runtime_cleanup_stays_inside_exclusive_lock(monkeypatch):
    locked=[];stopped=[]
    class Store:
        def __init__(self,*a):pass
        @contextmanager
        def locked(self):
            locked.append(True)
            try:yield
            finally:locked.clear()
        def json(self,*a):raise SupportError('invalid_store')
    class Children:
        def __init__(self,*a):pass
        def stop(self):stopped.append(bool(locked))
    monkeypatch.setattr(service,'PrivateStore',Store)
    monkeypatch.setattr(service,'NativeChildren',Children)
    with pytest.raises(SupportError):service.run_service()
    assert stopped == [True,True]


@pytest.mark.parametrize('failure,expected_error',[
    ('https','policy_unavailable'),
    ('malformed_policy','configuration_conflict'),
    ('native_start','tunnel_failed'),
    ('account','configuration_conflict'),
    ('unexpected_native','service_failed'),
])
def test_status_contract_error_then_policy_recovers_in_same_service_loop(monkeypatch,failure,expected_error):
    """Real loop/worker/lease logic with OS+HTTPS boundaries replaced, real DTO."""
    from endpoint_contracts.linux_support_access import LinuxSupportStatusReport
    from pc_agent.tests.linux.test_support_access import DEVICE,NOW,key,policy

    outgoing=[];rejected=[];native_starts=[];account_checks=[];instances=[]
    clock=[10.0]
    class Stop(Event):
        def __init__(self):super().__init__();self.waits=0
        def wait(self,timeout=None):
            self.waits+=1
            clock[0]+=31
            if self.waits>100:self.set()
            return super().wait(.001)  # Yield to the real bounded HTTPS worker.
    stop=Stop()
    config=dict(device_id=DEVICE,credential_id='e46fc348-c48c-415c-a86a-1dd60ef14e1b',
        support_token='eps1.'+'x'*64,origin='https://endpoint.sosnadmin.local',environment='production')
    class Store:
        def __init__(self,*_):self.state=None
        @contextmanager
        def locked(self):yield self
        def json(self,name,**_):return config if name=='config.json' else self.state
        def read(self,*_):return b'private test CA'
        def keys(self):return key(1),key(2)
        def save(self,_name,state):self.state=state
    class HTTPS:
        def __init__(self,*_):pass
        def request(self,action,token,body):
            outgoing.append(body.copy())
            try:LinuxSupportStatusReport.model_validate(body)
            except ValueError:
                rejected.append(body.copy())
                if len(outgoing)>=3:stop.set()
                raise SupportError('https_unavailable') from None  # Actual422 behavior.
            if len(outgoing)==1:
                if failure=='https':raise SupportError('https_unavailable')
                if failure=='malformed_policy':return policy(gateway_host='invalid.example'),NOW.timestamp()
            if len(outgoing)>=3:stop.set()
            return policy(),NOW.timestamp()
    class Children:
        def __init__(self,*_):self.active=False;instances.append(self)
        def stop(self):self.active=False
        def start(self,_policy,_deadline):
            native_starts.append(True)
            if failure=='native_start' and len(native_starts)==1:raise SupportError('child_start_failed')
            if failure=='unexpected_native' and len(native_starts)==1:raise ValueError('private native detail')
            self.active=True
        def alive(self):return self.active
        def connected(self):return self.active
    def account(*_):
        account_checks.append(True)
        if failure=='account' and len(account_checks)==1:raise SupportError('account_not_authorized')
    monkeypatch.setattr(service,'PrivateStore',Store)
    monkeypatch.setattr(service,'SupportHTTPS',HTTPS)
    monkeypatch.setattr(service,'NativeChildren',Children)
    monkeypatch.setattr(service,'validate_account',account)
    monkeypatch.setattr(service,'boot_time',lambda:clock[0])
    monkeypatch.setattr(service,'boot_id',lambda:'same-boot')
    monkeypatch.setattr(service.time,'time',lambda:NOW.timestamp())

    service.run_service(stop_event=stop)

    assert not rejected, 'Runtime emitted status outside the frozen Linux DTO'
    assert len(instances)==1 and len(outgoing)==3
    assert [body['last_error_code'] for body in outgoing]==[None,expected_error,None]
    assert outgoing[-1]['tunnel_connected'] is True
    assert native_starts  # Accepted recovery policy activated children in same loop.
