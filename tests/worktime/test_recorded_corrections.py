"""Employee records apply immediately; archived decisions stay immutable history."""
from datetime import UTC, date, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

from endpoint_server.worktime import service
from endpoint_server.worktime.domain import project_work
from endpoint_server.worktime.models import Approval, Audit, Correction, WorkEvent
from tests.worktime.test_store import db, person
from tests.worktime.test_api import client


async def test_unreviewed_correction_is_recorded_immediately_without_approval(db):
    target=await person(db);start=datetime(2026,10,26,4,tzinfo=UTC);key=uuid4()
    await service.transition(db,target,target,'start',uuid4(),start)
    await service.transition(db,target,target,'end',uuid4(),start+timedelta(hours=8))
    row=await service.request_correction(db,target,target,start,start+timedelta(hours=1),'BREAK','Wrong start',key,start+timedelta(hours=9))
    replay=await service.request_correction(db,target,target,start,start+timedelta(hours=1),'BREAK','Wrong start',key,start+timedelta(hours=10))
    report=await service.day_report(db,target,date(2026,10,26),start+timedelta(hours=11),include_activity=False)
    assert report['totals']['work_seconds']==7*3600 and report['totals']['break_seconds']==3600
    assert report['corrections'][0]['decision']=='recorded' and report['corrections'][0]['approval'] is None and replay.id==row.id
    assert report['work_intervals'][1]['source']=='recorded_correction'
    assert len((await db.scalars(select(WorkEvent))).all())==2 and (await db.scalars(select(Approval))).all()==[]
    assert [a.action for a in (await db.scalars(select(Audit))).all()].count('correction_recorded')==1


async def test_archived_approved_and_rejected_rows_keep_their_real_effects(db):
    target=await person(db);start=datetime(2026,10,26,4,tzinfo=UTC)
    await service.transition(db,target,target,'start',uuid4(),start)
    await service.transition(db,target,target,'end',uuid4(),start+timedelta(hours=8))
    approved=await service.request_correction(db,target,target,start,start+timedelta(hours=2),'BREAK','Historical accepted',uuid4(),start+timedelta(hours=9))
    rejected=await service.request_correction(db,target,target,start+timedelta(hours=2),start+timedelta(hours=3),'BREAK','Historical rejected',uuid4(),start+timedelta(hours=9))
    db.add_all([Approval(correction_id=approved.id,actor_id=uuid4(),decision='approved',comment='Archived',idempotency_key=uuid4(),fingerprint='a'*64,created_at=start+timedelta(hours=10)),
                Approval(correction_id=rejected.id,actor_id=uuid4(),decision='rejected',comment='Archived',idempotency_key=uuid4(),fingerprint='b'*64,created_at=start+timedelta(hours=12))])
    await db.flush()
    await service.request_correction(db,target,target,start,start+timedelta(hours=1),'OFF_PC','New record',uuid4(),start+timedelta(hours=11))
    report=await service.day_report(db,target,date(2026,10,26),start+timedelta(hours=13),include_activity=False)
    assert report['totals']==dict(work_seconds=7*3600,off_pc_seconds=3600,break_seconds=3600,scheduled_seconds=0)
    assert {c['decision'] for c in report['corrections']}=={'recorded','approved','rejected'}
    assert {'recorded_correction','approved_correction'}<={i['source'] for i in report['work_intervals']}
    assert len((await db.scalars(select(Approval))).all())==2


def test_actual_apply_time_and_id_tie_break_are_deterministic():
    start=datetime(2026,10,26,4,tzinfo=UTC)
    rows=[SimpleNamespace(id=UUID(int=1),started_at=start,ended_at=start+timedelta(hours=1),status='BREAK',applied_at=start+timedelta(hours=9),source='approved_correction'),
          SimpleNamespace(id=UUID(int=2),started_at=start,ended_at=start+timedelta(hours=1),status='OFF_PC',applied_at=start+timedelta(hours=9),source='recorded_correction')]
    first=project_work([],rows,start,start+timedelta(hours=1),start+timedelta(hours=10))
    assert first==project_work([],rows[::-1],start,start+timedelta(hours=1),start+timedelta(hours=10))
    assert first[1]['work_seconds']==3600 and first[0][0]['source']=='recorded_correction'


async def test_direct_decision_mutator_refuses_before_any_database_access():
    session=SimpleNamespace(scalar=AsyncMock(side_effect=AssertionError('No database access expected')))
    with pytest.raises(ValueError,match='decisions.*retired'):
        await service.decide_correction(session,SimpleNamespace(person_id=uuid4()),uuid4(),'approved','',uuid4(),datetime.now(UTC))
    session.scalar.assert_not_awaited()


async def test_recorded_api_history_and_retired_decision_endpoints(client):
    http,app,people=client
    body=dict(started_at='2026-09-05T04:00:00Z',ended_at='2026-09-05T05:00:00Z',status='WORKING',reason='Own record',idempotency_key=str(uuid4()))
    result=await http.post('/api/employee/worktime/corrections',json=body)
    assert result.status_code==200 and result.json()['decision']=='recorded' and result.json()['approval'] is None
    row=result.json()
    history=(await http.get('/api/employee/worktime/history?day=2026-09-05')).json()
    assert history['corrections'][0]['decision']=='recorded' and history['approvals']==[]
    assert (await http.get('/api/employee/worktime/approvals')).status_code==410
    assert (await http.post(f'/api/employee/worktime/corrections/{row["id"]}/decision',json=dict(decision='approved',comment='',idempotency_key=str(uuid4())))).status_code==410
    app.state.settings.oidc=SimpleNamespace(enabled=True)
    app.dependency_overrides.clear()
    assert (await http.get('/api/employee/worktime/approvals')).status_code==401


async def test_idempotent_post_preserves_archived_rejection_instead_of_relabeling_recorded(client):
    http,app,people=client;start=datetime(2026,9,5,4,tzinfo=UTC);key=uuid4()
    async with app.state.session_provider() as db:
        row=await service.request_correction(db,people[0],people[0],start,start+timedelta(hours=1),'WORKING','Original',key,start+timedelta(hours=2))
        db.add(Approval(correction_id=row.id,actor_id=uuid4(),decision='rejected',comment='Archived',idempotency_key=uuid4(),fingerprint='c'*64,created_at=start+timedelta(hours=3)))
        await db.commit()
    body=dict(started_at=start.isoformat(),ended_at=(start+timedelta(hours=1)).isoformat(),status='WORKING',reason='Original',idempotency_key=str(key))
    result=await http.post('/api/employee/worktime/corrections',json=body)
    assert result.status_code==200 and result.json()['decision']=='rejected' and result.json()['approval']['decision']=='rejected'
    report=(await http.get('/api/employee/worktime/day?day=2026-09-05')).json()
    assert report['totals']['work_seconds']==0
