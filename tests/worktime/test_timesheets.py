"""Finalized personnel ledgers survive source and technical retention independently."""
from datetime import UTC, date, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from endpoint_server.worktime.models import Timesheet, TimesheetDay, RetentionPolicy
from endpoint_server.worktime.service import (finalize_timesheet, timesheet_document, transition,
    request_correction, explain, retain_worktime, day_report, PersonnelHistoryExpired)
from tests.worktime.test_store import db, person


async def test_finalized_month_versions_are_immutable_after_corrections_and_retention(db):
    target, hr = await person(db),uuid4()
    start = datetime(2026,10,5,4,tzinfo=UTC)
    now = datetime(2026,11,1,tzinfo=UTC)
    await transition(db,target,target,'start',uuid4(),start)
    await transition(db,target,target,'end',uuid4(),start+timedelta(hours=8))
    await explain(db,target,target,start,start+timedelta(hours=1),'meeting','Verified meeting',uuid4(),None,start+timedelta(hours=9))
    key = uuid4()
    first = await finalize_timesheet(db,target,hr,'2026-10','Monthly approval',key,now)
    repeated = await finalize_timesheet(db,target,hr,'2026-10','Monthly approval',key,now+timedelta(minutes=1))
    assert repeated.id == first.id and first.version == 1
    original = await timesheet_document(db,first)
    assert original['totals']['work_seconds'] == 8*3600
    assert len(original['days']) == 31
    assert original['days'][4]['explanations'][0]['comment'] == 'Verified meeting'
    await request_correction(db,target,hr,start,start+timedelta(hours=1),'BREAK','HR recorded correction',uuid4(),now)
    second = await finalize_timesheet(db,target,hr,'2026-10','Revised after correction',uuid4(),now+timedelta(minutes=2))
    assert second.version == 2 and second.source_digest != first.source_digest
    assert (await timesheet_document(db,second))['totals']['work_seconds'] == 7*3600
    correction=(await timesheet_document(db,second))['days'][4]['corrections'][0]
    assert correction['decision']=='recorded' and correction['approval'] is None
    assert await timesheet_document(db,first) == original
    db.add(RetentionPolicy(actor_id=hr,retention_days=5,inactivity_threshold_seconds=1200,rationale='Approved source retention',created_at=now))
    await db.flush()
    await retain_worktime(db,now=now+timedelta(days=60))
    assert await timesheet_document(db,first) == original
    assert len((await db.scalars(select(TimesheetDay))).all()) == 62
    with pytest.raises(PersonnelHistoryExpired):
        await day_report(db,target,date(2026,10,5),now+timedelta(days=60),include_activity=False)


async def test_finalize_requires_closed_month_reason_and_nonexpired_sources(db):
    target,hr = await person(db),uuid4()
    now = datetime(2026,10,27,tzinfo=UTC)
    with pytest.raises(ValueError,match='closed'):
        await finalize_timesheet(db,target,hr,'2026-10','Current month',uuid4(),now)
    with pytest.raises(ValueError,match='reason'):
        await finalize_timesheet(db,target,target,'2026-09','',uuid4(),now)
    own=await finalize_timesheet(db,target,target,'2026-09','Own closed-month snapshot',uuid4(),now)
    assert own.finalized_by==target
    from endpoint_server.worktime.models import WorkState
    state = await db.get(WorkState,target)
    state.records_expired_before = datetime(2026,10,1,tzinfo=UTC)
    await db.flush()
    with pytest.raises(PersonnelHistoryExpired):
        await finalize_timesheet(db,target,hr,'2026-09','Expired source',uuid4(),now)
