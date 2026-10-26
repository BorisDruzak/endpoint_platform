from types import SimpleNamespace
from uuid import uuid4
from datetime import UTC, datetime

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_server.auth.employee_sessions import require_employee, EmployeePrincipal
from endpoint_server.db.base import Base
from endpoint_server.db.models import ConfirmedIdentity, ScopedRoleGrant
from endpoint_server.worktime.router import router


@pytest.fixture
async def client():
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    async with engine.begin() as connection:
        await connection.run_sync(lambda c: Base.metadata.create_all(c, tables=[t for n,t in Base.metadata.tables.items()
            if n.startswith('worktime_') or n in ('confirmed_identities','scoped_role_grants','devices','activity_intervals')]))
    provider = async_sessionmaker(engine, expire_on_commit=False)
    ids, dept = [uuid4() for _ in range(3)], uuid4()
    async with provider() as db:
        people = [ConfirmedIdentity(id=uuid4(),person_id=p,department_id=dept if i<2 else uuid4(),issuer='https://sso.example.test',
                    subject=str(p),ad_object_guid=uuid4(),state='active',confirmed_at=datetime.now(UTC)) for i,p in enumerate(ids)]
        db.add_all(people)
        db.add(ScopedRoleGrant(identity_id=people[0].id,role='manager',department_id=dept,granted_by=uuid4()))
        await db.commit()
    app = FastAPI()
    app.state.settings = SimpleNamespace(worktime_enabled=True)
    app.state.session_provider = provider
    app.include_router(router)
    async def resolve(issuer,subject,guid):
        match=next(person for person in people if person.issuer==issuer and person.subject==subject and person.ad_object_guid==guid)
        return SimpleNamespace(person_id=match.person_id,department_id=match.department_id)
    authority=SimpleNamespace(resolve=resolve)
    app.dependency_overrides[require_employee] = lambda: EmployeePrincipal(people[0], None,authority,'mfa','mfa')
    async with AsyncClient(transport=ASGITransport(app=app),base_url='https://test') as result:
        yield result, app, ids
    await engine.dispose()


async def test_manager_scope_no_arbitrary_self_write_or_identity_leak(client):
    http, app, people = client
    response = await http.get('/api/employee/worktime/people')
    assert {item['person_id'] for item in response.json()['people']} == {str(people[0]),str(people[1])}
    assert (await http.get(f'/api/employee/worktime/day?day=2026-10-26&person_id={people[2]}')).status_code == 403
    response = await http.post('/api/employee/worktime/transitions',json={'action':'start','idempotency_key':str(uuid4()),'person_id':str(people[1])})
    assert response.status_code == 422


async def test_feature_disabled_and_no_store(client):
    http, app, _ = client
    response = await http.get('/api/employee/worktime/day?day=2026-10-26')
    assert response.status_code == 200
    assert response.headers['cache-control'] == 'no-store'
    assert response.json()['coverage']['state'] == 'UNKNOWN'
    app.state.settings.worktime_enabled = False
    assert (await http.get('/api/employee/worktime/categories')).status_code == 404


async def test_expired_personnel_history_returns_410_instead_of_zero_totals(client):
    from endpoint_server.worktime.models import WorkState
    http,app,people = client
    async with app.state.session_provider() as db:
        db.add(WorkState(person_id=people[0],status='ENDED',records_expired_before=datetime(2026,10,27,tzinfo=UTC)))
        await db.commit()
    for path in ('day?day=2026-10-26','history?day=2026-10-26','month?month=2026-10'):
        result = await http.get('/api/employee/worktime/'+path)
        assert result.status_code == 410
        assert 'expired' in result.json()['detail']


async def test_history_omits_previous_day_carry_event(client):
    from endpoint_server.worktime.service import transition
    http,app,people = client
    async with app.state.session_provider() as db:
        await transition(db,people[0],people[0],'start',uuid4(),datetime(2026,10,25,18,tzinfo=UTC))
        await transition(db,people[0],people[0],'end',uuid4(),datetime(2026,10,26,5,tzinfo=UTC))
        await db.commit()
    response = await http.get('/api/employee/worktime/history?day=2026-10-26')
    assert response.status_code == 200
    assert [e['action'] for e in response.json()['events']] == ['end']


async def test_hr_correction_uses_scoped_target_preserves_actor_and_prevents_self_approval(client):
    from endpoint_server.worktime.models import Correction
    http,app,people = client
    principal = app.dependency_overrides[require_employee]()
    body = dict(started_at='2026-09-05T04:00:00Z',ended_at='2026-09-05T05:00:00Z',
        status='WORKING',reason='HR checked evidence',idempotency_key=str(uuid4()))
    assert (await http.post(f'/api/employee/worktime/people/{people[1]}/corrections',json=body)).status_code == 403
    async with app.state.session_provider() as db:
        db.add(ScopedRoleGrant(identity_id=principal.identity.id,role='hr',department_id=principal.identity.department_id,granted_by=uuid4()))
        await db.commit()
    result = await http.post(f'/api/employee/worktime/people/{people[1]}/corrections',json=body)
    assert result.status_code == 200
    record = result.json()
    assert record['person_id'] == str(people[1]) and record['actor_id'] == str(people[0])
    assert (await http.post(f'/api/employee/worktime/corrections/{record["id"]}/decision',
        json=dict(decision='approved',comment='',idempotency_key=str(uuid4())))).status_code == 409
    assert (await http.post(f'/api/employee/worktime/people/{people[2]}/corrections',json=body)).status_code == 403
    from dataclasses import replace
    app.dependency_overrides[require_employee] = lambda: replace(principal,achieved_acr='low')
    assert (await http.post(f'/api/employee/worktime/people/{people[1]}/corrections',json=body)).status_code == 403


async def test_finalized_month_api_version_list_read_export_and_scope(client):
    from endpoint_server.worktime.service import transition
    http,app,people = client
    principal = app.dependency_overrides[require_employee]()
    async with app.state.session_provider() as db:
        db.add(ScopedRoleGrant(identity_id=principal.identity.id,role='hr',department_id=principal.identity.department_id,granted_by=uuid4()))
        await transition(db,people[1],people[1],'start',uuid4(),datetime(2026,9,5,4,tzinfo=UTC))
        await transition(db,people[1],people[1],'end',uuid4(),datetime(2026,9,5,12,tzinfo=UTC))
        await db.commit()
    body = dict(month='2026-09',reason='Independent monthly approval',idempotency_key=str(uuid4()))
    result = await http.post(f'/api/employee/worktime/people/{people[1]}/timesheets/finalize',json=body)
    assert result.status_code == 200
    document = result.json()
    assert document['version'] == 1 and document['totals']['work_seconds'] == 8*3600
    assert len(document['days']) == 30
    assert (await http.post(f'/api/employee/worktime/people/{people[1]}/timesheets/finalize',json=body)).json()['id'] == document['id']
    listed = await http.get(f'/api/employee/worktime/timesheets?month=2026-09&person_id={people[1]}')
    assert listed.json()['timesheets'][0]['id'] == document['id']
    export = await http.get(f'/api/employee/worktime/timesheets/{document["id"]}/export')
    assert export.status_code == 200 and 'text/csv' in export.headers['content-type']
    assert 'attachment' in export.headers['content-disposition'] and document['source_digest'] in export.text
    assert ',28800,' in export.text
    assert (await http.get(f'/api/employee/worktime/timesheets/{document["id"]}')).json() == document
    assert (await http.post(f'/api/employee/worktime/people/{people[0]}/timesheets/finalize',json=body)).status_code == 403
    assert (await http.post(f'/api/employee/worktime/people/{people[2]}/timesheets/finalize',json=body)).status_code == 403
