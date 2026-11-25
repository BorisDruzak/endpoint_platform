"""Automatic reconnect work respects committed native removal, preserving history."""
from datetime import UTC, datetime, timedelta
from uuid import uuid4
import pytest
from sqlalchemy import select
from endpoint_contracts.installation_lifecycle import InstallationEventV1
from endpoint_server.context.connect_refresh import queue_connect_refreshes
from endpoint_server.context.models import ContextCollection, ContextSnapshot
from endpoint_server.db.models import DeviceSession
from endpoint_server.installation_lifecycle.service import accept_event
from tests.contracts.test_installation_lifecycle import event_data
from tests.server.test_installation_lifecycle import sessions, seed


@pytest.fixture
async def db(sessions):
    async with sessions() as session:
        async with session.bind.begin() as connection:
            await connection.run_sync(lambda sync: ContextCollection.metadata.create_all(sync,
                tables=[ContextCollection.__table__,ContextSnapshot.__table__,DeviceSession.__table__]))
        yield session


@pytest.mark.parametrize('state,expected',[('unknown',1),('installed',1),('removed',0)])
async def test_reconnect_admission_distinguishes_installation_state(db,state,expected):
    principal=await seed(db)
    now=datetime.now(UTC)
    if state!='unknown':
        body=InstallationEventV1.model_validate(event_data(device_id=str(principal.device.id),action=state))
        await accept_event(db,principal,body,request_id='reconnect-test',now=now)
    assert await queue_connect_refreshes(db,principal.device.id,{'context.network.collect'},now=now)==expected
    rows=(await db.scalars(select(ContextCollection))).all()
    assert len(rows)==expected
    if expected:
        assert rows[0].requested_by=='connect-refresh' and rows[0].profile=='network_v1'


async def test_removed_reconnect_preserves_queued_history_and_connection_evidence(db):
    principal=await seed(db);now=datetime.now(UTC)
    body=InstallationEventV1.model_validate(event_data(device_id=str(principal.device.id),action='removed'))
    await accept_event(db,principal,body,request_id='reconnect-test',now=now)
    queued=[]
    for index,requester in enumerate(('operator','connect-refresh')):
        row=ContextCollection(device_id=principal.device.id,profile='network_v1',requested_by=requester,
            idempotency_key=uuid4().hex,status='requested',requested_at=now-timedelta(hours=1),expires_at=now-timedelta(minutes=1))
        db.add(row);queued.append(row)
    connection=DeviceSession(device_id=principal.device.id,session_identifier=uuid4().hex,
        last_seen_at=now+timedelta(seconds=1),expires_at=now+timedelta(hours=1));db.add(connection)
    await db.commit()
    assert await queue_connect_refreshes(db,principal.device.id,{'context.network.collect'},now=now+timedelta(seconds=2))==0
    assert len((await db.scalars(select(ContextCollection))).all())==2
    for row in queued:
        await db.refresh(row)
        assert row.status=='requested' and row.failed_at is None and row.failure_code is None
    await db.refresh(connection)
    assert connection.closed_at is None and connection.last_seen_at.replace(tzinfo=UTC)==now+timedelta(seconds=1)
