from __future__ import annotations

import asyncio
import ipaddress
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from endpoint_contracts.gateway_ws import COMMAND_JOURNAL_FEATURE, COMMAND_JOURNAL_HEADER, CommandEnvelopeV1
from endpoint_server.context.models import ContextCollection, ContextSnapshot
from endpoint_server.db.models import Command, CommandDelivery, DeviceSession
from endpoint_contracts.power_events import POWER_EVENTS_FEATURE
from endpoint_server.gateway import ws_routes
from endpoint_server.gateway.command_service import CommandService, CommandStateRejected
from endpoint_server.power.models import PowerSourceState

from endpoint_server.main import create_app

from .conftest import agent_hello, gateway_settings, seed_device
from .test_stability_capacity import _envelope, _result


@pytest.mark.asyncio
@pytest.mark.parametrize("existing_command", [False, True])
async def test_expired_collection_cannot_block_delivery_of_fresh_work(
    session_provider: async_sessionmaker[AsyncSession], existing_command: bool,
) -> None:
    device = await seed_device(session_provider)
    now = datetime.now(UTC)
    session_id = uuid4()
    expired_id, fresh_id, command_id = uuid4(), uuid4(), uuid4()
    async with session_provider() as session:
        session.add(DeviceSession(id=session_id, device_id=device.id,
            session_identifier=f"expiry-{session_id.hex}", expires_at=now+timedelta(minutes=2),
            last_seen_at=now, source_address="192.168.101.20"))
        if existing_command:
            session.add(Command(id=command_id, device_id=device.id,
                command_identifier=f"expired-{command_id.hex}", command_kind="context.baseline.collect",
                status="delivered", created_at=now-timedelta(hours=2), expires_at=now-timedelta(hours=1)))
            await session.flush()
            session.add(CommandDelivery(id=uuid4(),command_id=command_id,
                delivery_identifier=f"expired-delivery-{command_id.hex}", status="delivered"))
        session.add_all([
            ContextCollection(id=expired_id,device_id=device.id,profile="baseline_v1",
                requested_by="connect-refresh",idempotency_key="expired-request",
                status="delivered" if existing_command else "requested",
                command_id=command_id if existing_command else None,
                requested_at=now-timedelta(hours=2),expires_at=now-timedelta(hours=1)),
            ContextCollection(id=fresh_id,device_id=device.id,profile="inventory_v1",
                requested_by="connect-refresh",idempotency_key="fresh-request",
                status="requested",requested_at=now,expires_at=now+timedelta(minutes=15)),
        ])
        await session.commit()
    sent=[]
    assert await CommandService(session_provider).deliver_next(device.id,session_id,sent.append,
        allowed_capabilities={"context.baseline.collect","context.inventory.collect"},agent_platform="windows_amd64")
    assert len(sent)==1
    assert sent[0].payload.capability=="context.inventory.collect"
    assert sent[0].payload.deadline_at>sent[0].payload.created_at
    async with session_provider() as session:
        expired=await session.get(ContextCollection,expired_id)
        assert expired.status=="expired"
        assert expired.failure_code=="collection_expired"
        assert expired.failed_at is not None
        if existing_command:
            assert (await session.get(Command,command_id)).status=="expired"
            delivery=await session.scalar(select(CommandDelivery).where(CommandDelivery.command_id==command_id))
            assert delivery.status=="expired"


@pytest.mark.asyncio
@pytest.mark.parametrize("session_open", [True, False], ids=["open", "closed"])
async def test_command_is_committed_before_websocket_send(
    session_provider: async_sessionmaker[AsyncSession], session_open: bool,
) -> None:
    device = await seed_device(session_provider)
    now = datetime.now(UTC)
    session_id = uuid4()
    async with session_provider() as session:
        session.add_all(
            (
                DeviceSession(
                    id=session_id,
                    device_id=device.id,
                    device_instance_id=None,
                    session_identifier=f"gateway-{session_id.hex}",
                    expires_at=now + timedelta(minutes=2),
                    closed_at=None if session_open else now,
                    last_seen_at=now,
                    source_address="192.168.101.20",
                ),
                ContextCollection(
                    id=uuid4(),
                    device_id=device.id,
                    profile="baseline_v1",
                    requested_by="gateway-test",
                    idempotency_key="gateway-delivery-test",
                    status="requested",
                    requested_at=now,
                ),
            )
        )
        await session.commit()
        engine = session.get_bind()

    observed: list[CommandEnvelopeV1] = []
    redundant_sql: list[str] = []
    device_selection_sql: list[str] = []

    def observe_sql(_conn, _cursor, statement, _params, _context, _many):
        sql = " ".join(statement.lower().split())
        if sql.startswith(("select devices.id from devices ", "select (exists (select context_collections.id")):
            device_selection_sql.append(sql)
        if sql.startswith("select ") and (
            "from context_collections where context_collections.id =" in sql
            or "from commands where commands.id =" in sql
            or "from command_deliveries where command_deliveries.command_id =" in sql
        ):
            redundant_sql.append(sql)
        if sql.startswith("update command_deliveries "):
            redundant_sql.append(sql)
        if sql.startswith("select endpoint_operations.") and "from endpoint_operations" in sql:
            redundant_sql.append(sql)

    async def send(envelope: CommandEnvelopeV1) -> None:
        async with session_provider() as inspection:
            commands = (await inspection.scalars(select(Command))).all()
            deliveries = (await inspection.scalars(select(CommandDelivery))).all()
            collection = (await inspection.scalars(select(ContextCollection))).one()
        assert len(commands) == 1
        assert len(deliveries) == 1
        assert collection.command_id == commands[0].id == deliveries[0].command_id == envelope.payload.command_id
        assert collection.status == "delivered"
        assert deliveries[0].device_session_id == session_id
        observed.append(envelope)

    event.listen(engine, "before_cursor_execute", observe_sql)
    try:
        service = CommandService(session_provider)
        if session_open:
            assert await service.deliver_next(device.id, session_id, send)
        else:
            with pytest.raises(CommandStateRejected, match="gateway session is unavailable"):
                await service.deliver_next(device.id, session_id, send)
    finally:
        event.remove(engine, "before_cursor_execute", observe_sql)

    if session_open:
        assert observed[0].payload.device_id == device.id
    else:
        assert observed == []
        async with session_provider() as inspection:
            assert (await inspection.scalars(select(Command))).all() == []
            assert (await inspection.scalars(select(CommandDelivery))).all() == []
            collection = (await inspection.scalars(select(ContextCollection))).one()
            assert collection.status == "requested"
            assert collection.command_id is None
    assert redundant_sql == []
    assert len(device_selection_sql) == 1
    assert device_selection_sql[0].startswith("select devices.id from devices ")
    assert "exists (select context_collections.id" in device_selection_sql[0]


@pytest.mark.asyncio
async def test_no_pending_command_sends_nothing(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    device = await seed_device(session_provider)
    sent: list[CommandEnvelopeV1] = []

    delivered = await CommandService(session_provider).deliver_next(
        device.id,
        uuid4(),
        sent.append,
    )

    assert not delivered
    assert sent == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("follow_up", "power_start", "requester"),
    [
        (False, None, "scheduler"), (True, None, "scheduler"),
        (True, "queued", "scheduler"), (True, "not_yet_sent", "scheduler"),
        (False, None, "operator"),
    ],
    ids=["single", "follow-up", "start-ready-during-power", "start-after-power-probe", "operator"],
)
async def test_idle_gateway_delivers_worker_request_without_heartbeat(
    session_provider, tmp_path, monkeypatch, follow_up, power_start, requester,
):
    initial_dispatch_done = asyncio.Event()
    heartbeat_done = asyncio.Event()
    socket_requests = []
    finish_power = asyncio.Event()
    post_power_probe = asyncio.Event()
    finish_post_power_probe = asyncio.Event()
    deliver_next = CommandService.deliver_next
    commit_power = ws_routes.commit_and_ack_power_events

    async def observe_power(*args, **kwargs):
        await commit_power(*args, **kwargs)
        await finish_power.wait()

    async def observe_dispatch(service, *args, **kwargs):
        if power_start and finish_power.is_set():
            post_power_probe.set()
            if power_start == "not_yet_sent":
                await finish_post_power_probe.wait()
        delivered = await deliver_next(service, *args, **kwargs)
        if not delivered:
            initial_dispatch_done.set()
        return delivered

    monkeypatch.setattr(CommandService, "deliver_next", observe_dispatch)
    if requester == "operator":
        from endpoint_server.gateway.connection_registry import ConnectionRegistry
        from endpoint_server.gateway.presence_service import PresenceService

        record_heartbeat = PresenceService.record_heartbeat
        request_dispatch = ConnectionRegistry.request_dispatch

        async def observe_heartbeat(presence, **kwargs):
            result = await record_heartbeat(presence, **kwargs)
            heartbeat_done.set()
            return result

        async def observe_request(registry, connection):
            socket_requests.append(connection.session_id)
            await request_dispatch(registry, connection)

        monkeypatch.setattr(PresenceService, "record_heartbeat", observe_heartbeat)
        monkeypatch.setattr(ConnectionRegistry, "request_dispatch", observe_request)
    if power_start:
        monkeypatch.setattr(ws_routes, "commit_and_ack_power_events", observe_power)
        async with session_provider() as db:
            connection = await db.connection()
            await connection.run_sync(lambda sync: PowerSourceState.__table__.create(sync))
            await db.commit()
    token = uuid4().hex
    device = await seed_device(session_provider, token=token)
    settings = replace(
        gateway_settings(artifact_root=tmp_path),
        allowed_agent_cidrs=(ipaddress.ip_network("127.0.0.0/8"),),
    )
    app = create_app(settings, session_provider)
    inbound, outbound = asyncio.Queue(), asyncio.Queue()
    scope = {
        "type": "websocket", "scheme": "wss", "path": "/agent/v1/connect",
        "root_path": "", "query_string": b"", "client": ("127.0.0.1", 54321),
        "server": ("localhost", 443), "subprotocols": [],
        "headers": [(b"authorization", f"Bearer {token}".encode()),
                    (COMMAND_JOURNAL_HEADER.lower().encode(), b"1"),
                    (b"x-forwarded-proto", b"https"), (b"x-forwarded-for", b"127.0.0.1")],
    }

    async def send(frame):
        await inbound.put({"type": "websocket.receive", "text": json.dumps(frame)})

    async def receive(kind):
        frame = await asyncio.wait_for(outbound.get(), timeout=4)
        assert frame["type"] == "websocket.send", frame
        envelope = json.loads(frame["text"])
        assert envelope["kind"] == kind, envelope
        return envelope["payload"]

    hello = agent_hello(device.id, instance_id=uuid4())
    features = [COMMAND_JOURNAL_FEATURE]
    if power_start:
        features.append(POWER_EVENTS_FEATURE)
    hello.update(capabilities=["context.health.collect"], protocol_features=features)
    async with app.router.lifespan_context(app):
        task = asyncio.create_task(app(scope, inbound.get, outbound.put))
        try:
            await inbound.put({"type": "websocket.connect"})
            assert (await asyncio.wait_for(outbound.get(), timeout=4))["type"] == "websocket.accept"
            await send(_envelope("agent_hello", 0, hello))
            handshake = await receive("gateway_hello")
            await asyncio.wait_for(initial_dispatch_done.wait(), timeout=4)
            now = datetime.now(UTC)
            if requester == "operator":
                await send(_envelope("heartbeat", 1, {
                    "schema_version": "agent_heartbeat_v1", "device_id": str(device.id),
                    "platform": "linux", "agent_version": hello["agent_version"], "reported_at": now.isoformat(),
                }))
                await asyncio.wait_for(heartbeat_done.wait(), timeout=4)
                assert socket_requests == []
            async with session_provider() as db:
                db.add(ContextCollection(
                    device_id=device.id, profile="health_v1", requested_by=requester,
                    idempotency_key="idle-worker-request", status="requested",
                    requested_at=now, expires_at=now + timedelta(minutes=5),
                ))
                await db.commit()

            command = (await receive("command"))["command_id"]
            follow_up_id = uuid4()
            if follow_up:
                async with session_provider() as db:
                    db.add(ContextCollection(
                        id=follow_up_id, device_id=device.id, profile="health_v1", requested_by="operator",
                        idempotency_key="pending-after-start", status="requested", requested_at=datetime.now(UTC),
                    ))
                    await db.commit()
            if power_start:
                batch_id = str(uuid4())
                await send(_envelope("power_event_batch", 1, {
                    "schema_version": "power_event_batch_v1",
                    "batch_id": batch_id,
                    "events": [],
                    "source_status": {
                        "schema_version": "power_source_status_v1",
                        "source": "systemd-journal",
                        "availability": "UNAVAILABLE",
                        "reported_at": now.isoformat(),
                        "loss_count": 2,
                    },
                }))
                assert (await receive("power_event_ack"))["batch_id"] == batch_id
            if power_start == "not_yet_sent":
                finish_power.set()
                await asyncio.wait_for(post_power_probe.wait(), timeout=4)
            feedback_reads = []

            def observe_feedback(_connection, _cursor, statement, *_):
                if asyncio.current_task() is task and statement.lstrip().startswith("SELECT"):
                    feedback_reads.append(" ".join(statement.lower().split()))

            async with session_provider() as db:
                engine = db.get_bind()
            event.listen(engine, "before_cursor_execute", observe_feedback)
            try:
                await send(_envelope("command_ack", 2, {
                    "schema_version": "agent_command_ack_v1", "device_id": str(device.id),
                    "command_id": command, "status": "running", "acknowledged_at": now.isoformat(),
                }))
                finish_power.set()
                assert (await receive("command_start"))["command_id"] == command
            finally:
                event.remove(engine, "before_cursor_execute", observe_feedback)
            assert sum("from device_sessions" in sql or "from commands" in sql for sql in feedback_reads) == 1
            if power_start == "queued":
                assert not post_power_probe.is_set()

            feedback_reads.clear()
            event.listen(engine, "before_cursor_execute", observe_feedback)
            try:
                await send(_result(device.id, command, 1))
                assert (await receive("result_ack"))["command_id"] == command
            finally:
                event.remove(engine, "before_cursor_execute", observe_feedback)
            assert sum("from commands where commands.id =" in sql for sql in feedback_reads) == 1
            assert sum("from context_collections where context_collections.command_id =" in sql for sql in feedback_reads) == 1
            assert not any("from command_results where command_results.id =" in sql for sql in feedback_reads)
            assert not any("from context_collections where context_collections.command_result_id =" in sql for sql in feedback_reads)
            finish_post_power_probe.set()
            if follow_up:
                next_command = await receive("command")
                async with session_provider() as db:
                    follow_up_collection = await db.get(ContextCollection, follow_up_id)
                    assert str(follow_up_collection.command_id) == next_command["command_id"]
            async with session_provider() as db:
                delivery = (await db.scalars(
                    select(CommandDelivery).where(CommandDelivery.command_id == UUID(command))
                )).one()
                assert str(delivery.device_session_id) == handshake["session_id"]
                assert len((await db.scalars(select(ContextSnapshot))).all()) == 1
        finally:
            finish_power.set()
            finish_post_power_probe.set()
            await inbound.put({"type": "websocket.disconnect", "code": 1000})
            await asyncio.wait_for(task, timeout=5)


@pytest.mark.asyncio
async def test_scheduled_candidates_require_matching_capability_and_live_request(session_provider):
    due, expired, manual, offline = [await seed_device(session_provider, token=uuid4().hex) for _ in range(4)]
    now = datetime.now(UTC)
    async with session_provider() as db:
        db.add_all(
            ContextCollection(
                device_id=device.id, profile="health_v1", requested_by=requester,
                idempotency_key="scheduled-selection", status="requested", requested_at=now - timedelta(minutes=5),
                expires_at=now + timedelta(seconds=remaining),
            )
            for device, requester, remaining in (
                (due, "scheduler", 60), (expired, "scheduler", -1),
                (manual, "admin", 60), (offline, "scheduler", 60),
            )
        )
        await db.commit()
    service = CommandService(session_provider)
    caps = frozenset({"context.health.collect"})
    assert await service.scheduled_pending_devices({due.id: frozenset({"context.inventory.collect"})}) == ()
    assert await service.scheduled_pending_devices({due.id: caps, expired.id: caps, manual.id: caps}) == tuple(sorted((due.id, manual.id)))


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["send", "commit_ack"])
async def test_scheduled_send_failure_replays_committed_delivery_on_reconnect(session_provider, monkeypatch, failure):
    from endpoint_contracts import AgentHelloV1
    from endpoint_server.gateway.connection_registry import ConnectionRegistry, GatewayConnection
    from endpoint_server.gateway.presence_service import PresenceService
    from endpoint_server.gateway.scheduled_dispatch import _deliver

    device = await seed_device(session_provider)
    hello = AgentHelloV1.model_validate(agent_hello(device.id, instance_id=uuid4()))
    presence = PresenceService(session_provider)
    first = await presence.open_session(device_id=device.id, hello=hello, source_address="192.168.101.20")
    async with session_provider() as db:
        db.add(ContextCollection(
            device_id=device.id, profile="health_v1", requested_by="scheduler",
            idempotency_key="broken-scheduled-send", status="requested", requested_at=datetime.now(UTC),
        ))
        await db.commit()

    class BrokenSocket:
        def __init__(self):
            self.closed = []

        async def send_json(self, _payload):
            raise OSError("peer disappeared")

        async def close(self, code):
            self.closed.append(code)

    socket = BrokenSocket()
    capabilities = frozenset({"context.health.collect"})
    registry = ConnectionRegistry()
    connection = GatewayConnection(device.id, first.session_id, socket, effective_capabilities=capabilities)
    connection.ready_for_dispatch.set()
    await registry.register(connection)
    service = CommandService(session_provider)
    original_delivery = service.deliver_next
    if failure == "commit_ack":
        # Reuse the actual transaction and interrupt its post-commit callback.
        # The dispatcher cannot know whether PostgreSQL committed in this case.
        async def lost_commit_ack(device_id, session_id, send, **kwargs):
            async def disconnected(_envelope):
                raise OSError("database commit acknowledgement was lost")
            return await original_delivery(device_id, session_id, disconnected, **kwargs)

        monkeypatch.setattr(service, "deliver_next", lost_commit_ack)
    await _deliver(service, registry, connection)
    monkeypatch.setattr(service, "deliver_next", original_delivery)
    assert socket.closed == [1011]
    assert not connection.ready_for_dispatch.is_set()

    async with session_provider() as db:
        delivery = (await db.scalars(select(CommandDelivery))).one()
        assert delivery.device_session_id == first.session_id

    second = await presence.open_session(device_id=device.id, hello=hello, source_address="192.168.101.20")
    sent = []
    assert await service.deliver_next(device.id, second.session_id, sent.append, allowed_capabilities=capabilities)
    assert sent[0].payload.command_id == delivery.command_id


@pytest.mark.asyncio
async def test_scheduled_delivery_waiting_to_send_checks_replacement_owner(session_provider):
    from endpoint_contracts import AgentHelloV1
    from endpoint_server.gateway.connection_registry import ConnectionRegistry, GatewayConnection
    from endpoint_server.gateway.presence_service import PresenceService
    from endpoint_server.gateway.scheduled_dispatch import _deliver

    device = await seed_device(session_provider)
    hello = AgentHelloV1.model_validate(agent_hello(device.id, instance_id=uuid4()))
    presence = PresenceService(session_provider)
    first = await presence.open_session(device_id=device.id, hello=hello, source_address="192.168.101.20")
    async with session_provider() as db:
        db.add(ContextCollection(
            device_id=device.id, profile="health_v1", requested_by="scheduler",
            idempotency_key="replace-during-send", status="requested", requested_at=datetime.now(UTC),
        ))
        await db.commit()

    waiting_to_send = asyncio.Event()

    class SendLock(asyncio.Lock):
        async def acquire(self):
            if self.locked():
                waiting_to_send.set()
            return await super().acquire()

    class Socket:
        def __init__(self):
            self.commands = []

        async def send_json(self, payload):
            self.commands.append(payload)

    capabilities = frozenset({"context.health.collect"})
    registry = ConnectionRegistry()
    old_socket = Socket()
    old = GatewayConnection(
        device.id, first.session_id, old_socket, effective_capabilities=capabilities, send_lock=SendLock(),
    )
    old.ready_for_dispatch.set()
    await registry.publish(old)
    service = CommandService(session_provider)
    async with asyncio.TaskGroup() as tasks:
        async with old.send_lock:
            tasks.create_task(_deliver(service, registry, old))
            await asyncio.wait_for(waiting_to_send.wait(), timeout=2)
            replacement = await presence.open_session(
                device_id=device.id, hello=hello, source_address="192.168.101.20",
            )
            new_socket = Socket()
            new = GatewayConnection(device.id, replacement.session_id, new_socket, effective_capabilities=capabilities)
            new.ready_for_dispatch.set()
            assert await registry.publish(new) is old

    assert old_socket.commands == []
    async with session_provider() as db:
        committed = (await db.scalars(select(CommandDelivery))).one()
        assert committed.device_session_id == first.session_id
    await _deliver(service, registry, new)
    assert [frame["payload"]["command_id"] for frame in new_socket.commands] == [str(committed.command_id)]
    async with session_provider() as db:
        replayed = (await db.scalars(select(CommandDelivery))).one()
        assert replayed.id == committed.id and replayed.device_session_id == replacement.session_id


@pytest.mark.asyncio
async def test_scheduled_scan_discovers_new_work_during_a_slow_delivery(session_provider, monkeypatch):
    from endpoint_server.gateway import scheduled_dispatch
    from endpoint_server.gateway.connection_registry import ConnectionRegistry, GatewayConnection

    first, second = [await seed_device(session_provider, token=uuid4().hex) for _ in range(2)]
    registry = ConnectionRegistry()
    first_started = asyncio.Event()
    second_started = asyncio.Event()
    blocked = asyncio.Event()
    cancelled_devices = set()
    first_calls = 0

    async def request_for(device):
        async with session_provider() as db:
            db.add(ContextCollection(
                device_id=device.id, profile="health_v1", requested_by="scheduler",
                idempotency_key="scan-during-delivery", status="requested", requested_at=datetime.now(UTC),
            ))
            await db.commit()
        connection = GatewayConnection(
            device.id, uuid4(), object(), effective_capabilities=frozenset({"context.health.collect"}),
        )
        connection.ready_for_dispatch.set()
        await registry.publish(connection)

    async def deliver(_service, _registry, connection):
        nonlocal first_calls
        if connection.device_id == first.id:
            first_calls += 1
            first_started.set()
        else:
            second_started.set()
        try:
            await blocked.wait()
        finally:
            cancelled_devices.add(connection.device_id)

    monkeypatch.setattr(scheduled_dispatch, "_POLL_SECONDS", 0.01)
    monkeypatch.setattr(scheduled_dispatch, "_deliver", deliver)
    await request_for(first)
    task = asyncio.create_task(scheduled_dispatch.run_scheduled_dispatch(registry, session_provider))
    try:
        await asyncio.wait_for(first_started.wait(), timeout=2)
        await request_for(second)
        await asyncio.wait_for(second_started.wait(), timeout=2)
        assert first_calls == 1
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert cancelled_devices == {first.id, second.id}


@pytest.mark.asyncio
async def test_dispatch_coalesces_activity_and_retires_replaced_requests():
    from endpoint_server.gateway.connection_registry import ConnectionRegistry, GatewayConnection

    registry = ConnectionRegistry(max_connections=2)
    owner = GatewayConnection(uuid4(), uuid4(), object())
    another = GatewayConnection(uuid4(), uuid4(), object())
    for connection in (owner, another):
        await registry.publish(connection)
        connection.ready_for_dispatch.set()

    await registry.request_dispatch(owner)
    assert await asyncio.wait_for(registry.next_dispatch(), timeout=1) is owner
    await registry.request_dispatch(owner)
    await registry.request_dispatch(owner)
    await registry.refresh_scheduled_dispatch((another,))
    assert await asyncio.wait_for(registry.next_dispatch(), timeout=1) is another
    await registry.finish_dispatch(another.device_id)
    await registry.refresh_scheduled_dispatch(())
    await registry.finish_dispatch(owner.device_id)

    assert await asyncio.wait_for(registry.next_dispatch(), timeout=1) is owner
    await registry.request_dispatch(owner)
    replacement = GatewayConnection(owner.device_id, uuid4(), object())
    replacement.ready_for_dispatch.set()
    assert await registry.publish(replacement) is owner
    await registry.request_dispatch(owner)
    await registry.finish_dispatch(owner.device_id)
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(registry.next_dispatch(), timeout=0.02)

    await registry.request_dispatch(replacement)
    assert await asyncio.wait_for(registry.next_dispatch(), timeout=1) is replacement
    await registry.finish_dispatch(replacement.device_id)


@pytest.mark.asyncio
async def test_scheduled_dispatch_counts_work_toward_next_scan_interval(monkeypatch):
    from types import SimpleNamespace

    from endpoint_server.gateway import scheduled_dispatch
    from endpoint_server.gateway.connection_registry import ConnectionRegistry

    now = 0.0
    starts = []

    async def sleep(delay):
        nonlocal now
        now += delay

    class Registry(ConnectionRegistry):
        async def connected(self):
            nonlocal now
            if len(starts) == 4:
                raise asyncio.CancelledError
            starts.append(now)
            now += (0.25, 1.5, 2.0, 0.1)[len(starts) - 1]
            return ()

    async def scan(_service, _capabilities):
        if len(starts) == 3:
            raise TimeoutError
        return ()

    monkeypatch.setattr(CommandService, "scheduled_pending_devices", scan)
    monkeypatch.setattr(scheduled_dispatch, "asyncio", SimpleNamespace(
        get_running_loop=lambda: SimpleNamespace(time=lambda: now),
        sleep=sleep,
        timeout=asyncio.timeout,
        Event=asyncio.Event,
        TaskGroup=asyncio.TaskGroup,
    ))
    with pytest.raises(asyncio.CancelledError):
        await scheduled_dispatch.run_scheduled_dispatch(Registry(), None)
    assert starts == [1.0, 2.0, 3.5, 6.5]


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["exception", "return"])
async def test_gateway_dispatch_recovers_after_unexpected_exit(session_provider, tmp_path, monkeypatch, caplog, failure):
    import endpoint_server.main as endpoint_main
    from endpoint_contracts import AgentHelloV1
    from endpoint_server.gateway.connection_registry import GatewayConnection
    from endpoint_server.gateway.presence_service import PresenceService

    device = await seed_device(session_provider)
    hello = AgentHelloV1.model_validate(agent_hello(device.id, instance_id=uuid4()))
    presence = PresenceService(session_provider)
    first = await presence.open_session(device_id=device.id, hello=hello, source_address="192.168.101.20")
    async with session_provider() as db:
        db.add(ContextCollection(
            device_id=device.id, profile="health_v1", requested_by="scheduler",
            idempotency_key="dispatch-exit", status="requested", requested_at=datetime.now(UTC),
        ))
        await db.commit()
    service = CommandService(session_provider)
    capabilities = frozenset({"context.health.collect"})
    failed, restarted, stopped = asyncio.Event(), asyncio.Event(), asyncio.Event()
    attempts = 0

    async def dispatch(*_):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            await failed.wait()

            async def lose_frame(_envelope):
                if failure == "exception":
                    raise RuntimeError("sensitive fixture value")

            await service.deliver_next(
                device.id, first.session_id, lose_frame, allowed_capabilities=capabilities,
            )
            return
        restarted.set()
        try:
            await asyncio.Future()
        finally:
            stopped.set()

    class Socket:
        def __init__(self):
            self.sent = []
            self.closed = []

        async def send_json(self, payload):
            self.sent.append(payload)

        async def close(self, code):
            self.closed.append(code)

    monkeypatch.setattr(endpoint_main, "run_scheduled_dispatch", dispatch)
    app = create_app(gateway_settings(artifact_root=tmp_path), session_provider)
    registry = app.state.gateway_connection_registry
    socket = Socket()
    owner = GatewayConnection(device.id, first.session_id, socket, effective_capabilities=capabilities)
    async with app.router.lifespan_context(app):
        await registry.publish(owner)
        owner.ready_for_dispatch.set()
        await registry.request_dispatch(owner)
        failed.set()
        await asyncio.wait_for(restarted.wait(), timeout=3)
        assert attempts == 2
        assert await registry.get(owner.device_id) is None
        assert socket.closed == [1001]
        assert [message["kind"] for message in socket.sent] == ["server_shutdown_notice"]
        async with session_provider() as db:
            committed = (await db.scalars(select(CommandDelivery))).one()
            assert committed.device_session_id == first.session_id

        replacement = await presence.open_session(
            device_id=device.id, hello=hello, source_address="192.168.101.20",
        )
        sent = []
        assert await service.deliver_next(
            device.id, replacement.session_id, sent.append, allowed_capabilities=capabilities,
        )
        assert [message.payload.command_id for message in sent] == [committed.command_id]
        async with session_provider() as db:
            replayed = (await db.scalars(select(CommandDelivery))).one()
            assert replayed.id == committed.id and replayed.device_session_id == replacement.session_id
    assert stopped.is_set()
    assert "Gateway dispatch stopped" in caplog.text
    assert "sensitive fixture value" not in caplog.text


@pytest.mark.asyncio
async def test_cancelled_dispatch_shutdown_releases_worker_lease(session_provider, tmp_path, monkeypatch):
    import endpoint_server.main as endpoint_main

    started, stopping = asyncio.Event(), asyncio.Event()

    async def delayed_dispatch_shutdown(*_):
        started.set()
        try:
            await asyncio.Future()
        finally:
            stopping.set()
            await asyncio.Future()

    monkeypatch.setattr(endpoint_main, "run_scheduled_dispatch", delayed_dispatch_shutdown)
    app = create_app(gateway_settings(artifact_root=tmp_path), session_provider)

    async def serve():
        async with app.router.lifespan_context(app):
            await asyncio.Future()

    task = asyncio.create_task(serve())
    await asyncio.wait_for(started.wait(), timeout=3)
    task.cancel()
    await asyncio.wait_for(stopping.wait(), timeout=3)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=3)
    lease = app.state.gateway_worker_lease
    lease.acquire()
    lease.release()


@pytest.mark.asyncio
@pytest.mark.parametrize("unexpected_profile", [False, True])
async def test_empty_wss_delivery_uses_one_read(session_provider, unexpected_profile):
    device = await seed_device(session_provider)
    async with session_provider() as db:
        if unexpected_profile:
            db.add(ContextCollection(
                device_id=device.id, profile="inventory_v1", requested_by="scheduler",
                idempotency_key="unsupported-inventory", status="requested", requested_at=datetime.now(UTC),
            ))
            await db.commit()
        engine = db.get_bind()

    statements = []

    def observe(_conn, _cursor, statement, _params, _context, _many):
        statements.append(statement)

    sent = []
    event.listen(engine, "before_cursor_execute", observe)
    try:
        assert not await CommandService(session_provider).deliver_next(
            device.id, uuid4(), sent.append, allowed_capabilities={"context.health.collect"},
        )
    finally:
        event.remove(engine, "before_cursor_execute", observe)
    assert sent == []
    assert len(statements) == 1
    assert "EXISTS" in statements[0]


@pytest.mark.asyncio
async def test_wss_delivery_expires_unsupported_collecting_request(session_provider):
    from endpoint_contracts import AgentHeartbeatV1, AgentHelloV1
    from endpoint_server.gateway.command_service import wss_work_available
    from endpoint_server.gateway.presence_service import PresenceService

    device = await seed_device(session_provider)
    presence = PresenceService(session_provider)
    connected = await presence.open_session(
        device_id=device.id,
        hello=AgentHelloV1.model_validate(agent_hello(device.id, instance_id=uuid4())),
        source_address="192.168.101.20",
    )
    collection_id = uuid4()
    now = datetime.now(UTC)
    async with session_provider() as db:
        db.add(ContextCollection(
            id=collection_id, device_id=device.id, profile="inventory_v1", requested_by="scheduler",
            idempotency_key="expired-collecting", status="collecting",
            requested_at=now - timedelta(minutes=2), expires_at=now - timedelta(seconds=1),
        ))
        await db.commit()

    supported = {"context.health.collect"}
    assert await presence.record_heartbeat(
        device_id=device.id,
        session_id=connected.session_id,
        heartbeat=AgentHeartbeatV1(
            schema_version="agent_heartbeat_v1", device_id=device.id,
            platform="linux", agent_version="4.0.0", reported_at=now,
        ),
        work_available=wss_work_available(device.id, supported),
    )
    assert not await CommandService(session_provider).deliver_next(
        device.id, connected.session_id, [].append, allowed_capabilities=supported,
    )
    async with session_provider() as db:
        collection = await db.get(ContextCollection, collection_id)
        assert collection is not None and collection.status == "expired"
