from datetime import UTC, date, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_contracts.worktime_companion import CompanionDeviceActionV1
from endpoint_server.db.base import Base
from endpoint_server.db.models import ConfirmedIdentity, Device
from endpoint_server.worktime.companion import CompanionDelivery, acknowledge, poll
from endpoint_server.worktime.models import ActivityBinding, Explanation, ExplanationRequest, WorkState, Schedule

NOW = datetime(2026, 10, 27, 8, tzinfo=UTC)
ORIGIN = 'https://endpoint.example.test'

class Authority:
    async def resolve(self, issuer, subject, guid):
        from types import SimpleNamespace
        return SimpleNamespace(person_id=UUID(subject),department_id=None)

AUTH = Authority()


@pytest.fixture
async def setup():
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    async with engine.begin() as connection:
        await connection.run_sync(lambda conn: Base.metadata.create_all(conn, tables=[table
            for name, table in Base.metadata.tables.items()
            if name.startswith('worktime_') or name in {'confirmed_identities', 'devices'}]))
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        person, device = uuid4(), uuid4()
        session.add(ConfirmedIdentity(person_id=person, issuer='https://sso.example.test', subject=str(person),
            ad_object_guid=uuid4(), state='active', confirmed_at=NOW))
        session.add(Device(id=device, device_identifier=str(device)))
        session.add(WorkState(person_id=person, status='ENDED'))
        session.add(Schedule(person_id=person,actor_id=person,idempotency_key=uuid4(),fingerprint='a'*64,
            effective_from=date(2026,10,1),definition={'weekdays':list(range(7)),'start':'00:00','end':'00:00','overrides':{}}))
        request = ExplanationRequest(person_id=person, started_at=NOW-timedelta(minutes=30), ended_at=NOW)
        session.add(request)
        session.add(ActivityBinding(person_id=person, device_id=device, user_key='domain\\alice',
            valid_from=NOW-timedelta(days=1), valid_until=NOW+timedelta(days=1), verified_by=uuid4(), proof_reference='verified'))
        await session.commit()
        yield session, person, device, request, factory
    await engine.dispose()


async def test_claim_reconnect_restart_and_ack_are_durable(setup):
    session, _, device, request, factory = setup
    first = await poll(session, device_id=device, user_login='DOMAIN\\Alice', origin=ORIGIN,authority_client=AUTH, now=NOW)
    assert first.request_id == request.id
    assert first.portal_url == f'{ORIGIN}/employee?day=2026-10-27&request_id={request.id}'
    assert (await poll(session, device_id=device, user_login='domain\\alice', origin=ORIGIN,authority_client=AUTH, now=NOW)).request_id is None
    await session.commit()
    async with factory() as restarted:
        retried = await poll(restarted, device_id=device, user_login='domain\\alice', origin=ORIGIN,authority_client=AUTH, now=NOW+timedelta(minutes=2))
        assert retried.request_id == request.id
        body = CompanionDeviceActionV1(request_id=request.id, lease_id=retried.lease_id, action='present', user_login='domain\\alice')
        await acknowledge(restarted, device_id=device, body=body, origin=ORIGIN,authority_client=AUTH, now=NOW+timedelta(minutes=2))
        await restarted.commit()
    assert (await poll(session, device_id=device, user_login='domain\\alice', origin=ORIGIN,authority_client=AUTH, now=NOW+timedelta(hours=1))).request_id is None


async def test_wrong_account_device_unknown_and_revoked_binding_never_open(setup):
    session, _, device, request, _ = setup
    for account, target in [('domain\\bob',device),('alice',device),('domain\\alice',uuid4())]:
        assert (await poll(session, device_id=target, user_login=account, origin=ORIGIN,authority_client=AUTH, now=NOW)).request_id is None
        with pytest.raises(HTTPException):
            await acknowledge(session, device_id=target,
                body=CompanionDeviceActionV1(request_id=request.id, lease_id=uuid4(), action='reason', user_login=account), origin=ORIGIN,authority_client=AUTH, now=NOW)
    assert (await poll(session, device_id=device, user_login='domain\\alice', origin=ORIGIN,authority_client=AUTH, now=NOW+timedelta(days=2))).request_id is None


async def test_saved_explanation_suppresses_offline_pending_and_old_action(setup):
    session, person, device, request, _ = setup
    await poll(session, device_id=device, user_login='domain\\alice', origin=ORIGIN,authority_client=AUTH, now=NOW)
    session.add(Explanation(person_id=person, actor_id=person, idempotency_key=uuid4(), fingerprint='a'*64,
        started_at=request.started_at, ended_at=request.ended_at, category_code='meeting', comment=''))
    await session.flush()
    assert (await poll(session, device_id=device, user_login='domain\\alice', origin=ORIGIN,authority_client=AUTH, now=NOW+timedelta(hours=1))).request_id is None
    with pytest.raises(HTTPException):
        await acknowledge(session, device_id=device,
            body=CompanionDeviceActionV1(request_id=request.id, lease_id=uuid4(), action='reason', user_login='domain\\alice'), origin=ORIGIN,authority_client=AUTH, now=NOW)


async def test_reason_and_later_never_reschedule_notification(setup):
    session, _, device, request, _ = setup
    claim=await poll(session, device_id=device, user_login='domain\\alice', origin=ORIGIN,authority_client=AUTH, now=NOW)
    for action in ['present','displayed', 'later', 'reason']:
        reply = await acknowledge(session, device_id=device,
            body=CompanionDeviceActionV1(request_id=request.id, lease_id=claim.lease_id, action=action, user_login='domain\\alice'), origin=ORIGIN,authority_client=AUTH, now=NOW)
        assert bool(reply.portal_url) == (action in {'present','reason'})
    assert (await poll(session, device_id=device, user_login='domain\\alice', origin=ORIGIN,authority_client=AUTH, now=NOW+timedelta(hours=1))).request_id is None


async def test_partial_explanation_does_not_hide_remaining_request_but_union_closes_it(setup):
    session, person, device, request, _ = setup
    midpoint = request.started_at+timedelta(minutes=1)
    def explanation(a,b):
        return Explanation(person_id=person, actor_id=person, idempotency_key=uuid4(), fingerprint='a'*64,
            started_at=a, ended_at=b, category_code='meeting', comment='')
    session.add(explanation(request.started_at,midpoint))
    await session.flush()
    assert (await poll(session, device_id=device, user_login='domain\\alice', origin=ORIGIN,authority_client=AUTH, now=NOW)).request_id == request.id
    session.add(explanation(midpoint,request.ended_at))
    await session.flush()
    assert (await poll(session, device_id=device, user_login='domain\\alice', origin=ORIGIN,authority_client=AUTH, now=NOW+timedelta(minutes=2))).request_id is None


async def test_routes_device_credentials_required_and_closed_schema(setup, monkeypatch):
    from types import SimpleNamespace
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient
    from endpoint_server.worktime import companion
    _, _, device, _, factory = setup
    app = FastAPI()
    app.state.settings = SimpleNamespace(worktime_enabled=True,public_base_url=ORIGIN)
    app.state.session_provider = factory
    app.state.helpdesk_identity_client=AUTH
    app.include_router(companion.router)
    payload = {'user_login':'domain\\alice', 'schema_version':'worktime_companion_poll_v1',
        'capability':'endpoint.worktime-companion.v1'}
    calls = []
    async def authenticate(session, request):
        calls.append(request.headers.get('authorization'))
        if request.headers.get('authorization') != 'Bearer core-device':
            raise HTTPException(401)
        return SimpleNamespace(device=SimpleNamespace(id=device))
    monkeypatch.setattr(companion,'_authenticate_device',authenticate)
    class Clock:
        @staticmethod
        def now(_zone): return NOW
    monkeypatch.setattr(companion,'datetime',Clock)
    async with AsyncClient(transport=ASGITransport(app=app),base_url=ORIGIN) as client:
        assert (await client.post('/agent/v1/gateway/worktime/next',json=payload)).status_code == 401
        headers={'Authorization':'Bearer core-device'}
        response=await client.post('/agent/v1/gateway/worktime/next',json=payload,headers=headers)
        assert response.status_code==200 and response.headers['cache-control']=='no-store'
        claim=response.json()
        assert claim['request_id'] and claim['lease_id']
        action={'schema_version':'worktime_companion_action_v1','user_login':'domain\\alice',
            'request_id':claim['request_id'],'lease_id':claim['lease_id'],'action':'present'}
        accepted=await client.post('/agent/v1/gateway/worktime/ack',json=action,headers=headers)
        assert accepted.status_code==200 and accepted.json()['lease_id']==claim['lease_id']
        action['action']='reason'
        opened=await client.post('/agent/v1/gateway/worktime/ack',json=action,headers=headers)
        assert opened.status_code==200 and opened.json()['portal_url'].startswith(ORIGIN+'/employee?')
        for extra in ['person_id','command','url']:
            assert (await client.post('/agent/v1/gateway/worktime/next',json={**payload,extra:str(uuid4())},headers=headers)).status_code==422
        app.state.settings.worktime_enabled=False
        assert (await client.post('/agent/v1/gateway/worktime/next',json=payload,headers=headers)).status_code==404


async def test_union_covered_prefix_advances_durably_to_501st_request(setup):
    from sqlalchemy import select
    session,person,device,request,_=setup
    # Each historical request is covered only by the union of two unlinked rows.
    for index in range(500):
        start=NOW-timedelta(hours=12)+timedelta(seconds=index*10)
        session.add(ExplanationRequest(person_id=person,started_at=start,ended_at=start+timedelta(seconds=6)))
        for left,right in [(start,start+timedelta(seconds=3)),(start+timedelta(seconds=3),start+timedelta(seconds=6))]:
            session.add(Explanation(person_id=person,actor_id=person,idempotency_key=uuid4(),fingerprint='a'*64,
                started_at=left,ended_at=right,category_code='meeting',comment=''))
    await session.flush()
    reply=await poll(session,device_id=device,user_login='domain\\alice',origin=ORIGIN,authority_client=AUTH,now=NOW)
    assert reply.request_id==request.id
    covered=list((await session.scalars(select(CompanionDelivery).where(CompanionDelivery.status=='covered'))).all())
    assert len(covered)==500


async def test_current_schedule_gate_and_revoked_identity(setup):
    from datetime import date
    from sqlalchemy import select
    from endpoint_server.worktime.models import Schedule
    session,person,device,request,_=setup
    session.add(Schedule(person_id=person,actor_id=person,idempotency_key=uuid4(),fingerprint='a'*64,
        effective_from=date(2026,10,27),definition={'weekdays':[0,1,2,3,4],'start':'08:00','end':'09:00','overrides':{}}))
    await session.flush()
    assert (await poll(session,device_id=device,user_login='domain\\alice',origin=ORIGIN,authority_client=AUTH,now=NOW)).request_id is None
    identity=await session.scalar(select(ConfirmedIdentity).where(ConfirmedIdentity.person_id==person))
    identity.state='revoked'
    assert (await poll(session,device_id=device,user_login='domain\\alice',origin=ORIGIN,authority_client=AUTH,now=NOW-timedelta(hours=4))).request_id is None


async def test_overnight_uses_previous_days_effective_schedule_and_holiday_override(setup):
    from sqlalchemy import select
    session,person,device,request,_=setup
    night=NOW-timedelta(hours=9)  # Tuesday 04:00 local, Monday's overnight shift.
    request.started_at,request.ended_at=night-timedelta(minutes=30),night
    for day,definition in [
        (date(2026,10,26),{'weekdays':[0],'start':'22:00','end':'06:00','overrides':{}}),
        (date(2026,10,27),{'weekdays':[1],'start':'09:00','end':'17:00','overrides':{}})]:
        session.add(Schedule(person_id=person,actor_id=person,idempotency_key=uuid4(),fingerprint='a'*64,
            effective_from=day,definition=definition))
    await session.flush()
    assert (await poll(session,device_id=device,user_login='domain\\alice',origin=ORIGIN,authority_client=AUTH,now=night)).request_id==request.id
    monday=await session.scalar(select(Schedule).where(Schedule.person_id==person,Schedule.effective_from==date(2026,10,26)))
    monday.definition={**monday.definition,'overrides':{'2026-10-26':None}}
    await session.flush()
    assert (await poll(session,device_id=device,user_login='domain\\alice',origin=ORIGIN,authority_client=AUTH,now=night+timedelta(minutes=2))).request_id is None


async def test_active_schedule_does_not_override_revocation_or_authority_failure(setup):
    from sqlalchemy import select
    session,person,device,_,_=setup
    assert (await poll(session,device_id=device,user_login='domain\\alice',origin=ORIGIN,now=NOW)).request_id is None
    class Offline:
        async def resolve(self,*args): raise OSError('authority unavailable')
    assert (await poll(session,device_id=device,user_login='domain\\alice',origin=ORIGIN,authority_client=Offline(),now=NOW)).request_id is None
    identity=await session.scalar(select(ConfirmedIdentity).where(ConfirmedIdentity.person_id==person))
    identity.revoked_at=NOW
    assert (await poll(session,device_id=device,user_login='domain\\alice',origin=ORIGIN,authority_client=AUTH,now=NOW)).request_id is None


async def test_expired_lease_fails_over_with_uuid_fencing_and_exclusive_presentation(setup):
    session,person,device,request,_=setup
    second=uuid4()
    session.add(Device(id=second,device_identifier=str(second)))
    session.add(ActivityBinding(person_id=person,device_id=second,user_key='domain\\alice',
        valid_from=NOW-timedelta(days=1),valid_until=NOW+timedelta(days=1),verified_by=uuid4(),proof_reference='verified-second-device'))
    await session.flush()
    first=await poll(session,device_id=device,user_login='domain\\alice',origin=ORIGIN,authority_client=AUTH,now=NOW)
    with pytest.raises(HTTPException):
        await acknowledge(session,device_id=device,body=CompanionDeviceActionV1(request_id=request.id,
            lease_id=first.lease_id,action='present',user_login='domain\\bob'),origin=ORIGIN,authority_client=AUTH,now=NOW)
    assert (await poll(session,device_id=second,user_login='domain\\alice',origin=ORIGIN,authority_client=AUTH,now=NOW)).request_id is None
    when=NOW+timedelta(minutes=2)
    replacement=await poll(session,device_id=second,user_login='domain\\alice',origin=ORIGIN,authority_client=AUTH,now=when)
    assert replacement.request_id==request.id and replacement.lease_id!=first.lease_id
    for action in ['present','displayed','reason','later','failed']:
        with pytest.raises(HTTPException):
            await acknowledge(session,device_id=device,body=CompanionDeviceActionV1(request_id=request.id,
                lease_id=first.lease_id,action=action,user_login='domain\\alice'),origin=ORIGIN,authority_client=AUTH,now=when)
    accepted=await acknowledge(session,device_id=second,body=CompanionDeviceActionV1(request_id=request.id,
        lease_id=replacement.lease_id,action='present',user_login='domain\\alice'),origin=ORIGIN,authority_client=AUTH,now=when)
    assert accepted.lease_id==replacement.lease_id
    # Once presentation is accepted, no other device may take it after timeout.
    assert (await poll(session,device_id=device,user_login='domain\\alice',origin=ORIGIN,authority_client=AUTH,now=NOW+timedelta(hours=1))).request_id is None
    await acknowledge(session,device_id=second,body=CompanionDeviceActionV1(request_id=request.id,
        lease_id=replacement.lease_id,action='failed',user_login='domain\\alice'),origin=ORIGIN,authority_client=AUTH,now=when)
    recovered=await poll(session,device_id=device,user_login='domain\\alice',origin=ORIGIN,authority_client=AUTH,now=when)
    assert recovered.request_id==request.id and recovered.lease_id not in {first.lease_id,replacement.lease_id}


async def test_huge_covered_prefix_progress_survives_session_restart(setup):
    from sqlalchemy import select
    session,person,device,request,factory=setup
    for index in range(1001):
        start=NOW-timedelta(hours=12)+timedelta(seconds=index*10)
        session.add(ExplanationRequest(person_id=person,started_at=start,ended_at=start+timedelta(seconds=6)))
        for left,right in [(start,start+timedelta(seconds=3)),(start+timedelta(seconds=3),start+timedelta(seconds=6))]:
            session.add(Explanation(person_id=person,actor_id=person,idempotency_key=uuid4(),fingerprint='a'*64,
                started_at=left,ended_at=right,category_code='meeting',comment=''))
    await session.flush()
    assert (await poll(session,device_id=device,user_login='domain\\alice',origin=ORIGIN,authority_client=AUTH,now=NOW)).request_id is None
    assert len((await session.scalars(select(CompanionDelivery).where(CompanionDelivery.status=='covered'))).all())==1000
    await session.commit()
    async with factory() as restarted:
        assert (await poll(restarted,device_id=device,user_login='domain\\alice',origin=ORIGIN,authority_client=AUTH,now=NOW)).request_id==request.id
