"""Real PostgreSQL Device-first reconnect/removal transaction ordering."""
import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from alembic import command
from sqlalchemy import select, text

from endpoint_contracts.installation_lifecycle import InstallationEventV1
from endpoint_server.context.connect_refresh import queue_connect_refreshes
from endpoint_server.context.models import ContextCollection
from endpoint_server.db.models import Device, DeviceCredential, DeviceSession
from endpoint_server.db.session import AsyncSessionProvider
from endpoint_server.installation_lifecycle.service import accept_event
from tests.contracts.test_installation_lifecycle import event_data
from tests.server.test_installation_lifecycle import seed, next_event
from tests.server.test_update_postgresql import update_migration_database_urls, _alembic_config

pytestmark=pytest.mark.usefixtures('preserve_migration_loggers')


def test_removal_commit_wins_waiting_reconnect_before_collection_locks(update_migration_database_urls):
    url,_=update_migration_database_urls
    command.upgrade(_alembic_config(url),'head')
    async def scenario():
        provider=AsyncSessionProvider(url);pending=None
        try:
            now=datetime.now(UTC)
            async with provider() as session:
                principal=await seed(session);device_id=principal.device.id;credential_id=principal.credential.id
                installed=InstallationEventV1.model_validate(event_data(device_id=str(device_id)))
                await accept_event(session,principal,installed,request_id='race-installed',now=now)
                old=ContextCollection(device_id=device_id,profile='network_v1',requested_by='operator',
                    idempotency_key=uuid4().hex,status='requested',requested_at=now-timedelta(hours=1),
                    expires_at=now-timedelta(minutes=1));session.add(old)
                connection=DeviceSession(device_id=device_id,session_identifier=uuid4().hex,
                    last_seen_at=now+timedelta(seconds=1),expires_at=now+timedelta(hours=1));session.add(connection)
                await session.commit();old_id=old.id;connection_id=connection.id
            started=asyncio.Event();waiter_pid=[]
            async def reconnect():
                async with provider() as session:
                    # Previously loaded Device must not defeat the locked fresh check.
                    await session.get(Device,device_id)
                    waiter_pid.append(await session.scalar(text('SELECT pg_backend_pid()')))
                    started.set()
                    created=await queue_connect_refreshes(session,device_id,{'context.network.collect'},now=now+timedelta(seconds=2))
                    await session.commit()
                    return created
            async with provider() as removing:
                device=await removing.scalar(select(Device).where(Device.id==device_id).with_for_update())
                credential=await removing.scalar(select(DeviceCredential).where(DeviceCredential.id==credential_id).with_for_update())
                await accept_event(removing,SimpleNamespace(device=device,credential=credential),next_event(installed,'removed'),
                    request_id='race-removed',now=now+timedelta(seconds=1))
                pending=asyncio.create_task(reconnect())
                try:
                    await asyncio.wait_for(started.wait(),5)
                    async with provider() as observer:
                        waiting=None
                        for _ in range(100):
                            waiting=(await observer.execute(text('SELECT wait_event_type, query FROM pg_stat_activity WHERE pid=:pid'),
                                {'pid':waiter_pid[0]})).one()
                            if waiting.wait_event_type=='Lock': break
                            await asyncio.sleep(0.01)
                        assert waiting.wait_event_type=='Lock', waiting
                        assert 'FROM devices' in waiting.query and 'FOR UPDATE' in waiting.query
                        # A connection producer waiting for Device cannot already own
                        # collection/advisory locks in the opposite order.
                        advisory=await observer.scalar(text("SELECT count(*) FROM pg_locks WHERE pid=:pid AND locktype='advisory' AND granted"),{'pid':waiter_pid[0]})
                        collection_locks=await observer.scalar(text("SELECT count(*) FROM pg_locks WHERE pid=:pid AND relation='context_collections'::regclass AND granted"),{'pid':waiter_pid[0]})
                        assert advisory==0 and collection_locks==0
                    await removing.commit()
                    assert await asyncio.wait_for(pending,10)==0
                finally:
                    if pending is not None and not pending.done():
                        pending.cancel();await asyncio.gather(pending,return_exceptions=True)
            async with provider() as session:
                rows=(await session.scalars(select(ContextCollection).where(ContextCollection.device_id==device_id))).all()
                assert len(rows)==1 and rows[0].id==old_id and rows[0].status=='requested'
                assert rows[0].failed_at is None and rows[0].failure_code is None
                connection=await session.get(DeviceSession,connection_id)
                assert connection.closed_at is None and connection.last_seen_at==now+timedelta(seconds=1)
        finally:
            if pending is not None and not pending.done():
                pending.cancel();await asyncio.gather(pending,return_exceptions=True)
            await provider.close()
    asyncio.run(scenario())
