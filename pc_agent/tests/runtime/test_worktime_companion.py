import json
from datetime import date
from uuid import uuid4

import pytest
from pydantic import ValidationError

from endpoint_contracts.worktime_companion import CompanionPollV1, CompanionReplyV1
from pc_agent.worktime_companion import handle_request, parse_request


def test_closed_local_capability_rejects_user_supplied_identity_and_commands():
    payload = CompanionPollV1().model_dump()
    assert parse_request(json.dumps(payload).encode()) is not None
    for key, value in [('user_login','domain\\victim'),('person_id',str(uuid4())),('url','https://evil.test'),('command','cmd.exe')]:
        assert parse_request(json.dumps({**payload,key:value}).encode()) is None
    assert parse_request(b'{"schema_version":"worktime_companion_poll_v1","schema_version":"worktime_companion_poll_v1"}') is None


def test_os_derived_peer_login_only_and_missing_peer_fails_closed():
    calls = []
    def handler(message, login):
        calls.append(login)
        return CompanionReplyV1()
    payload = CompanionPollV1().model_dump_json().encode()
    handle_request(payload, user_login='domain\\alice', handler=handler)
    handle_request(payload, user_login=None, handler=handler)
    assert calls == ['domain\\alice']


@pytest.mark.parametrize('url', ['http://endpoint.test/employee?day=2026-10-27&request_id='+str(uuid4()),
    'https://user:password@endpoint.test/employee?day=2026-10-27&request_id='+str(uuid4()),
    'https://endpoint.test/employee?person_id='+str(uuid4()), 'https://endpoint.test/admin'])
def test_untrusted_portal_target_is_rejected(url):
    with pytest.raises(ValidationError):
        CompanionReplyV1(portal_url=url)


def test_user_restart_receipt_suppresses_duplicate_and_requires_server_action_before_browser(tmp_path):
    from pc_agent.platform.worktime_user import UserCompanion
    request = uuid4()
    url = f'https://endpoint.test/employee?day=2026-10-27&request_id={request}'
    notified, opened, actions = [], [], []
    def exchange(payload):
        data = json.loads(payload)
        action = data.get('action')
        actions.append(action)
        return CompanionReplyV1(request_id=request,lease_id=request, day=date(2026,10,27), portal_url=url if action == 'reason' else None).model_dump_json()
    path = tmp_path/'receipts'
    UserCompanion(exchange, lambda: notified.append(True) or 'reason', state_path=path, open_url=opened.append).run_once()
    UserCompanion(exchange, lambda: notified.append(True) or 'later', state_path=path, open_url=opened.append).run_once()
    assert notified == [True] and opened == [url]
    assert actions == [None, 'present', 'displayed', 'reason', None, 'present', 'displayed']


def test_offline_action_cannot_open_cached_url(tmp_path):
    from pc_agent.platform.worktime_user import UserCompanion
    request = uuid4()
    opened = []
    def exchange(payload):
        data = json.loads(payload)
        return CompanionReplyV1(request_id=request if data.get('action') in {None,'present'} else None,lease_id=request).model_dump_json()
    UserCompanion(exchange, lambda:'reason', state_path=tmp_path/'receipt', open_url=opened.append).run_once()
    assert not opened


def test_windows_listener_uses_os_identity_and_rejects_wrong_session_before_handler(monkeypatch):
    from pc_agent.platform.windows import activity_api
    from pc_agent.platform.windows.local_ipc import LocalIpcRejected
    seen=[]
    sentinel=object()
    monkeypatch.setattr(activity_api,'authorize_pipe_client',lambda _:sentinel)
    monkeypatch.setattr(activity_api,'resolve_user_login',lambda identity:'domain\\alice' if identity is sentinel else None)
    def handler(message, login):
        seen.append(login)
        return CompanionReplyV1()
    args=dict(ingress=None,policy_provider=lambda:None,on_observation=lambda _:None,companion_handler=handler)
    payload=CompanionPollV1().model_dump_json().encode()
    assert activity_api.handle_local_sensor_payload(object(),payload,**args).schema_version=='worktime_companion_reply_v1'
    assert seen==['domain\\alice']
    def reject(_):
        raise LocalIpcRejected('wrong session')
    monkeypatch.setattr(activity_api,'authorize_pipe_client',reject)
    assert activity_api.handle_local_sensor_payload(object(),payload,**args).error_code=='IDENTITY_MISMATCH'
    assert seen==['domain\\alice']


def test_linux_companion_uses_only_fresh_kernel_authenticated_session(monkeypatch):
    import struct
    from types import SimpleNamespace
    from pc_agent.platform.linux import sensor_listener
    monkeypatch.setattr(sensor_listener.socket,'SO_PEERCRED',17,raising=False)
    peer=SimpleNamespace(user_login='domain\\alice',session=SimpleNamespace(active=True,locked=False))
    captured={}
    class Listener:
        def __init__(self, handler, **kwargs): captured['handler']=handler
    monkeypatch.setattr(sensor_listener,'LinuxSensorListener',Listener)
    monkeypatch.setattr(sensor_listener,'read_frame',lambda *_args,**_kwargs:CompanionPollV1().model_dump_json().encode())
    monkeypatch.setattr(sensor_listener,'authenticate_connection',lambda _: (peer,(123,1001,1001)))
    replies=[]
    monkeypatch.setattr(sensor_listener,'write_frame',lambda _,payload:replies.append(payload))
    calls=[]
    sensor_listener.create_activity_listener(ingress=None,policy_provider=lambda:None,on_observation=lambda _:None,
        companion_handler=lambda msg,login:calls.append(login) or CompanionReplyV1())
    connection=SimpleNamespace(getsockopt=lambda *_:struct.pack('iII',123,1001,1001))
    captured['handler'](connection)
    peer.session.locked=True
    captured['handler'](connection)
    peer.session.locked=False
    peer.session.active=False
    captured['handler'](connection)
    assert calls==['domain\\alice'] and len(replies)==3


def test_failed_native_startup_releases_receipt_and_never_acks_displayed(tmp_path):
    from pc_agent.platform.worktime_user import UserCompanion
    request=uuid4()
    sent=[]
    def exchange(payload):
        sent.append(json.loads(payload))
        return CompanionReplyV1(request_id=request,lease_id=request).model_dump_json()
    def broken(): raise OSError('notification unavailable')
    companion=UserCompanion(exchange,broken,state_path=tmp_path/'receipt')
    with pytest.raises(OSError): companion.run_once()
    assert not (tmp_path/'receipt').read_text()
    assert [item.get('action') for item in sent]==[None,'present','failed']


def test_stale_fenced_lease_cannot_start_native_notice(tmp_path):
    from pc_agent.platform.worktime_user import UserCompanion
    request,lease=uuid4(),uuid4()
    notified=[]
    def exchange(payload):
        data=json.loads(payload)
        if data.get('action')=='present':
            return CompanionReplyV1().model_dump_json()
        return CompanionReplyV1(request_id=request,lease_id=lease).model_dump_json()
    companion=UserCompanion(exchange,lambda:notified.append(True),state_path=tmp_path/'receipt')
    companion.run_once()
    assert not notified and not companion.state_path.exists()


@pytest.mark.asyncio
async def test_core_https_producer_consumer_uses_device_bearer_and_os_login_only(monkeypatch, tmp_path):
    import asyncio
    from contextlib import suppress
    from types import SimpleNamespace
    import aiohttp
    import ssl
    from endpoint_contracts.worktime_companion import CompanionActionV1, CompanionDeviceActionV1, CompanionDevicePollV1
    from pc_agent.worktime_companion import CoreCompanionBridge
    calls=[]
    request=uuid4()
    origin='https://endpoint.test'
    reply=CompanionReplyV1(request_id=request,lease_id=request,day=date(2026,10,27),
        portal_url=f'{origin}/employee?day=2026-10-27&request_id={request}')
    class Response:
        status=200
        content_length=100
        @property
        def content(self): return self
        async def read(self,n): return reply.model_dump_json().encode()
        async def __aenter__(self): return self
        async def __aexit__(self,*args): pass
    class Session:
        async def __aenter__(self): return self
        async def __aexit__(self,*args): pass
        def post(self,url,**kwargs):
            calls.append((url,kwargs))
            model=CompanionDevicePollV1 if url.endswith('/next') else CompanionDeviceActionV1
            body=model.model_validate(kwargs['json'])
            assert body.user_login=='domain\\alice'
            assert kwargs['headers']=={'Authorization':'Bearer core-device-only'}
            assert kwargs['allow_redirects'] is False
            return Response()
    monkeypatch.setattr(aiohttp,'ClientSession',lambda **kwargs:Session())
    monkeypatch.setattr(aiohttp,'TCPConnector',lambda **kwargs:object())
    monkeypatch.setattr(ssl,'create_default_context',lambda **kwargs:object())
    bridge=CoreCompanionBridge()
    task=asyncio.create_task(bridge.serve(SimpleNamespace(ca_file=tmp_path/'ca',endpoint_origin=origin),'core-device-only'))
    try:
        await asyncio.sleep(0)
        result=await asyncio.to_thread(bridge.handle,CompanionPollV1(),'domain\\alice')
        assert result.request_id==request
        # A second sampling tick does not create another HTTP poll.
        assert (await asyncio.to_thread(bridge.handle,CompanionPollV1(),'domain\\alice')).request_id is None
        result=await asyncio.to_thread(bridge.handle,CompanionActionV1(request_id=request,lease_id=request,action='reason'),'domain\\alice')
        assert result.portal_url==reply.portal_url
        assert len(calls)==2
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError): await task
    assert bridge.handle(CompanionPollV1(),'domain\\alice').request_id is None


def test_linux_native_notice_uses_fixed_unprivileged_dbus_action_interface(monkeypatch):
    from types import SimpleNamespace
    from pc_agent.platform.linux import worktime_notification
    calls=[]
    monkeypatch.setattr(worktime_notification,'os',SimpleNamespace(getuid=lambda:1001,geteuid=lambda:1001,
        environ={'DBUS_SESSION_BUS_ADDRESS':'unix:path=/run/user/1001/bus'}))
    def run(argv,**kwargs):
        calls.append((argv,kwargs))
        return SimpleNamespace(returncode=0,stdout='reason\n')
    monkeypatch.setattr(worktime_notification.subprocess,'run',run)
    assert worktime_notification.notify()=='reason'
    argv,kwargs=calls[0]
    assert argv[0]=='/usr/bin/notify-send'
    assert '--action=reason=Указать причину' in argv and '--action=later=Позже' in argv
    assert kwargs['timeout']==50 and 'shell' not in kwargs
    monkeypatch.setattr(worktime_notification,'os',SimpleNamespace(getuid=lambda:0,geteuid=lambda:0,environ={}))
    with pytest.raises(OSError): worktime_notification.notify()
    assert len(calls)==1


@pytest.mark.asyncio
@pytest.mark.parametrize('failure_phase',['factory','context'])
async def test_optional_client_startup_failure_retries_with_bounded_backoff_and_propagates_cancel(
        monkeypatch,tmp_path,caplog,failure_phase):
    import asyncio
    import ssl
    from types import SimpleNamespace
    import aiohttp
    from pc_agent import worktime_companion
    attempts=[]
    closed=[]
    waiting=asyncio.Queue()
    resume=asyncio.Queue()
    async def wait_retry(seconds):
        await waiting.put(seconds)
        await resume.get()
    class BrokenContext:
        async def __aenter__(self): raise TypeError('sensitive-startup-message')
        async def __aexit__(self,*args): pass
    def factory(**kwargs):
        attempts.append(True)
        if failure_phase=='factory': raise OSError('sensitive-startup-message')
        return BrokenContext()
    monkeypatch.setattr(aiohttp,'ClientSession',factory)
    monkeypatch.setattr(aiohttp,'TCPConnector',lambda **kwargs:SimpleNamespace(close=lambda:closed.append(True)))
    monkeypatch.setattr(ssl,'create_default_context',lambda **kwargs:object())
    monkeypatch.setattr(worktime_companion,'_wait_retry',wait_retry,raising=False)
    bridge=worktime_companion.CoreCompanionBridge()
    task=asyncio.create_task(bridge.serve(SimpleNamespace(ca_file=tmp_path/'ca',endpoint_origin='https://endpoint.test'),'device-secret'))
    try:
        for index,expected in enumerate([5,10,20,40,80,160,300,300]):
            assert await asyncio.wait_for(waiting.get(),1)==expected
            assert len(attempts)==index+1 and len(closed)==index+1
            assert not task.done()
            assert bridge.handle(CompanionPollV1(),'domain\\alice').request_id is None
            if index<7: await resume.put(True)
        assert 'sensitive-startup-message' not in caplog.text and 'device-secret' not in caplog.text
        assert {record.error_type for record in caplog.records if record.name==worktime_companion.__name__}=={
            'OSError' if failure_phase=='factory' else 'TypeError'}
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
