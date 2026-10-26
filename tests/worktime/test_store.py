from datetime import UTC, date, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_server.db.base import Base
from endpoint_server.db.models import ConfirmedIdentity, Device
from endpoint_server.activity.analytics_models import ActivityInterval
from endpoint_server.worktime.models import WorkState, WorkEvent, Explanation, Correction, Approval, ActivityBinding, Schedule, ExplanationRequest
from endpoint_server.worktime.service import transition, explain, request_correction, decide_correction, day_report, generate_requests, pending_requests, activity_segments, fingerprint


@pytest.fixture
async def db():
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    async with engine.begin() as connection:
        await connection.run_sync(lambda conn: Base.metadata.create_all(conn, tables=[
            table for name, table in Base.metadata.tables.items() if name.startswith('worktime_') or name in ('confirmed_identities','devices','activity_intervals','activity_daily','activity_cursors')]))
    async with async_sessionmaker(engine, expire_on_commit=False)() as session:
        yield session
    await engine.dispose()


async def person(db):
    person_id = uuid4()
    db.add(ConfirmedIdentity(person_id=person_id, issuer='https://sso.example.test', subject=str(person_id),
        ad_object_guid=uuid4(), state='active', confirmed_at=datetime.now(UTC)))
    db.add(WorkState(person_id=person_id, status='ENDED'))
    await db.commit()
    return person_id


async def test_idempotency_invalid_transition_two_device_no_double_count(db):
    target = await person(db)
    key = uuid4()
    now = datetime(2026, 10, 26, 4, tzinfo=UTC)
    first = await transition(db, target, target, 'start', key, now)
    repeated = await transition(db, target, target, 'start', key, now + timedelta(seconds=2))
    assert first.id == repeated.id
    with pytest.raises(ValueError):
        await transition(db, target, target, 'start', uuid4(), now + timedelta(seconds=3))
    assert len((await db.scalars(select(WorkEvent))).all()) == 1


async def test_correction_approval_preserves_original_and_history(db):
    target, reviewer = await person(db), uuid4()
    start = datetime(2026, 10, 26, 4, tzinfo=UTC)
    await transition(db, target, target, 'start', uuid4(), start)
    await transition(db, target, target, 'end', uuid4(), start + timedelta(hours=8))
    correction = await request_correction(db, target, target, start, start + timedelta(hours=1), 'BREAK', 'Wrong start', uuid4(), start + timedelta(hours=9))
    with pytest.raises(ValueError):
        await decide_correction(db, correction, target, 'approved', '', uuid4(), start + timedelta(hours=9))
    await decide_correction(db, correction, reviewer, 'approved', 'Verified', uuid4(), start + timedelta(hours=9))
    assert len((await db.scalars(select(WorkEvent))).all()) == 2
    assert len((await db.scalars(select(Correction))).all()) == 1
    assert len((await db.scalars(select(Approval))).all()) == 1
    report = await day_report(db, target, date(2026, 10, 26), start + timedelta(hours=10), include_activity=False)
    assert report['totals']['work_seconds'] == 7 * 3600
    assert report['totals']['break_seconds'] == 3600
    assert report['coverage']['state'] == 'UNKNOWN'
    assert report['activity_intervals'][0]['state'] == 'UNKNOWN'


async def test_explanation_comment_and_no_category_work_credit(db):
    target = await person(db)
    start = datetime(2026, 10, 26, 4, tzinfo=UTC)
    with pytest.raises(ValueError):
        await explain(db, target, target, start, start + timedelta(hours=1), 'other', '', uuid4(), None, start + timedelta(hours=2))
    item = await explain(db, target, target, start, start + timedelta(hours=1), 'meeting', 'Meeting', uuid4(), None, start + timedelta(hours=2))
    assert item.category_code == 'meeting'
    report = await day_report(db, target, date(2026, 10, 26), start + timedelta(hours=2), include_activity=False)
    assert report['totals']['work_seconds'] == 0


async def technical(db, target, *, binding=True, two_devices=False):
    start = datetime(2026, 10, 26, 4, tzinfo=UTC)
    devices = [Device(id=uuid4(),device_identifier=str(uuid4())) for _ in range(2 if two_devices else 1)]
    db.add_all(devices)
    await db.flush()
    for device in devices:
        if binding:
            db.add(ActivityBinding(person_id=target,device_id=device.id,user_key='DOMAIN\\verified',
                valid_from=start-timedelta(hours=1),valid_until=start+timedelta(hours=10),verified_by=uuid4(),proof_reference='Pilot verification record'))
        db.add_all([ActivityInterval(device_id=device.id,user_key='DOMAIN\\verified',user_login='DOMAIN\\verified',
            started_at=start,ended_at=start+timedelta(minutes=20),last_observed_at=start+timedelta(minutes=20),session_state='IDLE'),
            ActivityInterval(device_id=device.id,user_key='DOMAIN\\verified',user_login='DOMAIN\\verified',
            started_at=start+timedelta(minutes=20),ended_at=start+timedelta(minutes=25),last_observed_at=start+timedelta(minutes=25),session_state='ACTIVE')])
    db.add(Schedule(person_id=target,actor_id=target,idempotency_key=uuid4(),fingerprint='a'*64,effective_from=date(2026,10,1),
        definition=dict(weekdays=[0,1,2,3,4],start='08:00',end='17:00',overrides={})))
    await db.flush()
    return start,devices


async def test_two_devices_deduplicated_and_request_is_durable_idempotent(db):
    target = await person(db)
    start,_ = await technical(db,target,two_devices=True)
    now = start+timedelta(hours=1)
    created = await generate_requests(db,target,start.date(),now)
    assert len(created) == 1
    assert await generate_requests(db,target,start.date(),now) == []


    assert len(await pending_requests(db,target)) == 1
    report = await day_report(db,target,start.date(),now)
    assert report['coverage']['measured_seconds'] == 1500
    assert report['totals']['work_seconds'] == 0
    assert all('user_key' not in item and 'device_id' not in item for item in report['activity_intervals'])
    await explain(db,target,target,start,start+timedelta(minutes=20),'meeting','',uuid4(),None,now)
    assert await pending_requests(db,target) == []
    assert await generate_requests(db,target,start.date(),now) == []


async def test_multiple_explanations_cover_request_union_without_repeated_notification(db):
    target = await person(db)
    start,_ = await technical(db,target)
    now = start+timedelta(hours=1)
    await generate_requests(db,target,start.date(),now)
    for left,right in [(start,start+timedelta(minutes=10)),(start+timedelta(minutes=10),start+timedelta(minutes=20))]:
        await explain(db,target,target,left,right,'meeting','',uuid4(),None,now)
    assert await pending_requests(db,target) == []


async def test_pending_queue_pages_past_union_covered_history_without_writes(db):
    target = await person(db)
    start = datetime(2026,10,26,4,tzinfo=UTC)
    for index in range(501):
        left = start + timedelta(seconds=index*10)
        db.add(ExplanationRequest(person_id=target,started_at=left,ended_at=left+timedelta(seconds=6)))
        for a,b in ((left,left+timedelta(seconds=3)),(left+timedelta(seconds=3),left+timedelta(seconds=6))):
            db.add(Explanation(person_id=target,actor_id=target,idempotency_key=uuid4(),fingerprint='a'*64,
                started_at=a,ended_at=b,category_code='meeting',comment=''))
    # Equal timestamps exercise the ID tie-breaker when the result spans pages.
    later = start + timedelta(hours=2)
    wanted = [ExplanationRequest(person_id=target,started_at=later,ended_at=later+timedelta(minutes=20,seconds=index))
              for index in range(501)]
    db.add_all(wanted)
    await db.commit()
    before = list((await db.scalars(select(ExplanationRequest).order_by(ExplanationRequest.id))).all())
    result = await pending_requests(db,target)
    assert len(result) == 500
    assert [r.id for r in result] == sorted(r.id for r in wanted)[:500]
    assert not db.new and not db.dirty and not db.deleted
    after = list((await db.scalars(select(ExplanationRequest).order_by(ExplanationRequest.id))).all())
    assert [r.id for r in after] == [r.id for r in before]


async def test_day_report_pending_queue_is_scoped_before_result_limit(db):
    target = await person(db)
    previous = datetime(2026,10,25,4,tzinfo=UTC)
    db.add_all([ExplanationRequest(person_id=target,started_at=previous+timedelta(seconds=index),
        ended_at=previous+timedelta(minutes=20,seconds=index)) for index in range(500)])
    today = previous+timedelta(days=1)
    wanted = ExplanationRequest(person_id=target,started_at=today,ended_at=today+timedelta(minutes=20))
    db.add(wanted)
    await db.commit()
    report = await day_report(db,target,today.date(),today+timedelta(hours=1),include_activity=False)
    assert [r['id'] for r in report['pending_explanations']] == [str(wanted.id)]


async def test_pending_queue_excess_history_fails_explicitly_without_mutation(db, monkeypatch):
    from endpoint_server.worktime import service
    monkeypatch.setattr(service,'MAX_PENDING_CANDIDATES',5,raising=False)
    target = await person(db)
    start = datetime(2026,10,26,4,tzinfo=UTC)
    for index in range(6):
        left = start+timedelta(seconds=index*10)
        db.add(ExplanationRequest(person_id=target,started_at=left,ended_at=left+timedelta(seconds=6)))
        for a,b in ((left,left+timedelta(seconds=3)),(left+timedelta(seconds=3),left+timedelta(seconds=6))):
            db.add(Explanation(person_id=target,actor_id=target,idempotency_key=uuid4(),fingerprint='a'*64,
                started_at=a,ended_at=b,category_code='meeting',comment=''))
    await db.commit()
    with pytest.raises(ValueError,match='safe history size'):
        await pending_requests(db,target)
    assert not db.new and not db.dirty and not db.deleted


async def test_unverified_login_never_attributes_or_requests(db):
    target = await person(db)
    start,_ = await technical(db,target,binding=False)
    now = start+timedelta(hours=1)
    report = await day_report(db,target,start.date(),now)
    assert report['coverage']['state'] == 'UNKNOWN'
    assert await generate_requests(db,target,start.date(),now) == []


async def test_other_os_session_suppresses_ambiguous_notification(db):
    target = await person(db)
    start,devices = await technical(db,target)
    db.add(ActivityInterval(device_id=devices[0].id,user_key='DOMAIN\\other',user_login='DOMAIN\\other',
        started_at=start+timedelta(minutes=1),ended_at=start+timedelta(minutes=2),
        last_observed_at=start+timedelta(minutes=2),session_state='ACTIVE'))
    await db.flush()
    assert await generate_requests(db,target,start.date(),start+timedelta(hours=1)) == []


async def test_new_schedule_does_not_invent_yesterdays_overnight_work(db):
    target = await person(db)
    db.add(Schedule(person_id=target,actor_id=target,idempotency_key=uuid4(),fingerprint='a'*64,effective_from=date(2026,10,27),
        definition=dict(weekdays=[0,1,2,3,4],start='22:00',end='06:00',overrides={})))
    await db.flush()
    report = await day_report(db,target,date(2026,10,27),datetime(2026,10,28,tzinfo=UTC),include_activity=False)
    assert report['totals']['scheduled_seconds'] == 2*3600


async def test_overlapping_reassigned_overnight_schedules_count_elapsed_time_once(db):
    target = await person(db)
    for effective,start,end in [(date(2026,10,1),'22:00','06:00'),(date(2026,10,27),'00:00','23:00')]:
        db.add(Schedule(person_id=target,actor_id=target,idempotency_key=uuid4(),fingerprint='a'*64,effective_from=effective,
            definition=dict(weekdays=[0,1,2,3,4],start=start,end=end,overrides={})))
    await db.flush()
    report = await day_report(db,target,date(2026,10,27),datetime(2026,10,28,tzinfo=UTC),include_activity=False)
    assert report['totals']['scheduled_seconds'] == 23*3600


async def test_pending_request_after_technical_retention_survives(db):
    from endpoint_server.activity.analytics_policy import AnalyticsPolicy
    from endpoint_server.activity.analytics_store import retain_analytics
    target = await person(db)
    start,_ = await technical(db,target)
    created = await generate_requests(db,target,start.date(),start+timedelta(hours=1))
    await explain(db,target,target,start,start+timedelta(minutes=20),'meeting','',uuid4(),created[0].id,start+timedelta(hours=1))
    await retain_analytics(db,policy=AnalyticsPolicy(),now=start+timedelta(days=500))
    assert len((await db.scalars(select(Explanation))).all()) == 1
    assert len((await db.scalars(select(ExplanationRequest))).all()) == 1


async def test_personnel_retention_requires_separate_explicit_policy(db):
    from endpoint_server.worktime.models import RetentionPolicy
    from endpoint_server.worktime.service import retain_worktime
    target = await person(db)
    start = datetime(2026,10,26,4,tzinfo=UTC)
    await transition(db,target,target,'start',uuid4(),start)
    await transition(db,target,target,'end',uuid4(),start+timedelta(hours=8))
    await explain(db,target,target,start,start+timedelta(hours=1),'meeting','',uuid4(),None,start+timedelta(hours=8))
    future = start+timedelta(days=100)
    assert await retain_worktime(db,now=future) == 0
    assert len((await db.scalars(select(Explanation))).all()) == 1
    db.add(RetentionPolicy(actor_id=target,retention_days=30,inactivity_threshold_seconds=1200,rationale='Approved pilot policy',created_at=start+timedelta(days=1)))
    await db.flush()
    assert await retain_worktime(db,now=future) >= 1
    assert (await db.scalars(select(Explanation))).all() == []
    # The carry-forward event preserves state at the retention boundary.
    events = (await db.scalars(select(WorkEvent))).all()
    assert len(events) == 1 and events[0].status == 'ENDED'
    from endpoint_server.worktime.service import PersonnelHistoryExpired
    with pytest.raises(PersonnelHistoryExpired):
        await day_report(db,target,start.date(),future,include_activity=False)
    # Disabling cleanup later cannot resurrect purged history as apparent zero work.
    db.add(RetentionPolicy(actor_id=target,retention_days=None,inactivity_threshold_seconds=1200,
        rationale='Pause deletion',created_at=future))
    await db.flush()
    assert await retain_worktime(db,now=future) == 0
    with pytest.raises(PersonnelHistoryExpired):
        await day_report(db,target,start.date(),future,include_activity=False)
