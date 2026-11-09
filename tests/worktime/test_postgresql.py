"""Real PostgreSQL serialization against a unique disposable migrated database."""
import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from endpoint_server.db.models import ConfirmedIdentity
from endpoint_server.worktime.models import Timesheet, TimesheetDay, WorkEvent, WorkState
from endpoint_server.worktime.service import finalize_timesheet, transition
from tests.server.test_admin_auth import auth_database_url

pytestmark = pytest.mark.usefixtures('preserve_migration_loggers')


def test_concurrent_devices_and_retries_serialize_on_confirmed_person(auth_database_url):
    async def exercise():
        engine = create_async_engine(auth_database_url)
        factory = async_sessionmaker(engine,expire_on_commit=False)
        target = uuid4()
        now = datetime(2026,10,26,4,tzinfo=UTC)
        try:
            async with factory() as db:
                db.add(ConfirmedIdentity(person_id=target,issuer='https://sso.example.test',subject=str(target),
                    ad_object_guid=uuid4(),state='active',confirmed_at=now))
                await db.commit()

            async def write(key):
                async with factory() as db:
                    try:
                        await db.execute(text("SET LOCAL lock_timeout='5s'"))
                        event = await transition(db,target,target,'start',key,now)
                        await db.commit()
                        return event.id
                    except ValueError:
                        await db.rollback()
                        return None
            keys = [uuid4(),uuid4()]
            outcomes = await asyncio.gather(*(write(key) for key in keys))
            assert sum(value is not None for value in outcomes) == 1
            winner = keys[0] if outcomes[0] is not None else keys[1]
            assert (await asyncio.gather(write(winner),write(winner)))[0] == next(v for v in outcomes if v is not None)
            async with factory() as db:
                events = list((await db.scalars(select(WorkEvent).where(WorkEvent.person_id==target))).all())
                state = await db.get(WorkState,target)
                assert len(events) == 1 and state.status == 'WORKING'
                await transition(db,target,target,'end',uuid4(),now+timedelta(hours=8))
                await db.commit()
        finally:
            await engine.dispose()
    asyncio.run(exercise())


def test_recorded_corrections_and_guarded_migration_preserve_real_postgres_history(auth_database_url):
    from importlib import import_module
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from sqlalchemy.exc import DBAPIError
    from endpoint_server.worktime.models import Approval, Correction
    from endpoint_server.worktime.service import request_correction, day_report, timesheet_document

    async def exercise():
        engine=create_async_engine(auth_database_url);factory=async_sessionmaker(engine,expire_on_commit=False)
        target,reviewer=uuid4(),uuid4();start=datetime(2026,9,5,4,tzinfo=UTC);now=datetime(2026,10,1,tzinfo=UTC)
        migration=import_module('endpoint_server.db.migrations.versions.0043_worktime_recorded')
        def migrate(connection,direction):
            with Operations.context(MigrationContext.configure(connection)):
                getattr(migration,direction)()
        try:
            async with factory() as db:
                db.add(ConfirmedIdentity(person_id=target,issuer='https://sso.example.test',subject=str(target),ad_object_guid=uuid4(),state='active',confirmed_at=start));await db.flush()
                await transition(db,target,target,'start',uuid4(),start)
                await transition(db,target,target,'end',uuid4(),start+timedelta(hours=8))
                recorded=await request_correction(db,target,target,start,start+timedelta(hours=1),'BREAK','Recorded immediately',uuid4(),now)
                rejected=await request_correction(db,target,target,start+timedelta(hours=1),start+timedelta(hours=2),'BREAK','Archived rejected',uuid4(),now)
                approved=await request_correction(db,target,target,start+timedelta(hours=2),start+timedelta(hours=3),'BREAK','Archived approved',uuid4(),now)
                db.add_all([Approval(correction_id=rejected.id,actor_id=reviewer,decision='rejected',comment='Historical',idempotency_key=uuid4(),fingerprint='a'*64,created_at=now),
                            Approval(correction_id=approved.id,actor_id=reviewer,decision='approved',comment='Historical',idempotency_key=uuid4(),fingerprint='b'*64,created_at=now)])
                await db.flush();report=await day_report(db,target,start.date(),now,include_activity=False)
                assert report['totals']['work_seconds']==6*3600 and report['totals']['break_seconds']==2*3600
                assert {c['decision'] for c in report['corrections']}=={'recorded','approved','rejected'}
                first=await finalize_timesheet(db,target,reviewer,'2026-09','Closed month',uuid4(),now);await db.commit();saved=await timesheet_document(db,first)
            async with engine.begin() as connection:
                await connection.run_sync(lambda c:migrate(c,'downgrade'))
                assert await connection.scalar(text("SELECT count(*) FROM pg_constraint WHERE conname='ck_worktime_timesheet_independent'"))==1
                await connection.run_sync(lambda c:migrate(c,'upgrade'))
            async with factory() as db:
                own=await finalize_timesheet(db,target,target,'2026-09','No independent reviewer required',uuid4(),now+timedelta(minutes=1));await db.commit()
                assert own.finalized_by==target and await timesheet_document(db,first)==saved
            with pytest.raises(DBAPIError,match='self-finalized history exists'):
                async with engine.begin() as connection:await connection.run_sync(lambda c:migrate(c,'downgrade'))
            async with factory() as db:
                assert await db.scalar(text("SELECT count(*) FROM pg_constraint WHERE conname='ck_worktime_timesheet_independent'"))==0
                assert await timesheet_document(db,first)==saved and len((await db.scalars(select(Timesheet))).all())==2
                assert len((await db.scalars(select(Approval))).all())==2 and len((await db.scalars(select(Correction))).all())==3
        finally:await engine.dispose()
    asyncio.run(exercise())


def test_finalized_month_concurrent_versions_and_database_immutability(auth_database_url):
    from sqlalchemy import delete, update
    from sqlalchemy.exc import DBAPIError

    async def exercise():
        engine = create_async_engine(auth_database_url)
        factory = async_sessionmaker(engine,expire_on_commit=False)
        target,reviewer = uuid4(),uuid4()
        start = datetime(2026,9,5,4,tzinfo=UTC)
        now = datetime(2026,10,1,tzinfo=UTC)
        try:
            async with factory() as db:
                db.add(ConfirmedIdentity(person_id=target,issuer='https://sso.example.test',subject=str(target),
                    ad_object_guid=uuid4(),state='active',confirmed_at=start))
                await db.flush()
                await transition(db,target,target,'start',uuid4(),start)
                await transition(db,target,target,'end',uuid4(),start+timedelta(hours=8))
                await db.commit()

            async def finalize(key):
                async with factory() as db:
                    await db.execute(text("SET LOCAL lock_timeout='5s'"))
                    row = await finalize_timesheet(db,target,reviewer,'2026-09','Independent approval',key,now)
                    await db.commit()
                    return row.id,row.version

            versions = await asyncio.gather(finalize(uuid4()),finalize(uuid4()))
            assert sorted(v for _,v in versions) == [1,2]
            async with factory() as db:
                sheets = (await db.scalars(select(Timesheet).where(Timesheet.person_id==target))).all()
                assert all(row.totals['work_seconds']==8*3600 for row in sheets)
                assert len((await db.scalars(select(TimesheetDay))).all()) == 60
                with pytest.raises(DBAPIError,match='immutable'):
                    await db.execute(update(Timesheet).where(Timesheet.id==sheets[0].id).values(reason='Overwrite'))
                await db.rollback()
                with pytest.raises(DBAPIError,match='immutable'):
                    await db.execute(delete(TimesheetDay))
                await db.rollback()
        finally:
            await engine.dispose()
    asyncio.run(exercise())
