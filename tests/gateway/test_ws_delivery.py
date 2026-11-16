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
from endpoint_server.gateway.command_service import CommandService

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
async def test_command_is_committed_before_websocket_send(
    session_provider: async_sessionmaker[AsyncSession],
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
                    closed_at=None,
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

    observed: list[CommandEnvelopeV1] = []

    async def send(envelope: CommandEnvelopeV1) -> None:
        async with session_provider() as inspection:
            commands = (await inspection.scalars(select(Command))).all()
            deliveries = (await inspection.scalars(select(CommandDelivery))).all()
        assert len(commands) == 1
        assert len(deliveries) == 1
        assert deliveries[0].device_session_id == session_id
        observed.append(envelope)

    delivered = await CommandService(session_provider).deliver_next(
        device.id,
        session_id,
        send,
    )

    assert delivered
    assert observed[0].payload.device_id == device.id


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
@pytest.mark.parametrize("follow_up", [False, True])
async def test_idle_gateway_delivers_worker_request_without_heartbeat(
    session_provider, tmp_path, monkeypatch, follow_up,
):
    initial_dispatch_done = asyncio.Event()
    deliver_next = CommandService.deliver_next

    async def observe_initial_dispatch(service, *args, **kwargs):
        delivered = await deliver_next(service, *args, **kwargs)
        if not delivered:
            initial_dispatch_done.set()
        return delivered

    monkeypatch.setattr(CommandService, "deliver_next", observe_initial_dispatch)
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
    hello.update(capabilities=["context.health.collect"], protocol_features=[COMMAND_JOURNAL_FEATURE])
    async with app.router.lifespan_context(app):
        task = asyncio.create_task(app(scope, inbound.get, outbound.put))
        try:
            await inbound.put({"type": "websocket.connect"})
            assert (await asyncio.wait_for(outbound.get(), timeout=4))["type"] == "websocket.accept"
            await send(_envelope("agent_hello", 0, hello))
            handshake = await receive("gateway_hello")
            await asyncio.wait_for(initial_dispatch_done.wait(), timeout=4)
            now = datetime.now(UTC)
            async with session_provider() as db:
                db.add(ContextCollection(
                    device_id=device.id, profile="health_v1", requested_by="scheduler",
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
                        idempotency_key="pending-after-start", status="requested", requested_at=now,
                    ))
                    await db.commit()
            await send(_envelope("command_ack", 2, {
                "schema_version": "agent_command_ack_v1", "device_id": str(device.id),
                "command_id": command, "status": "running", "acknowledged_at": now.isoformat(),
            }))
            assert (await receive("command_start"))["command_id"] == command
            await send(_result(device.id, command, 1))
            assert (await receive("result_ack"))["command_id"] == command
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
    assert await service.scheduled_pending_devices({due.id: caps, expired.id: caps, manual.id: caps}) == (due.id,)


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
    device = await seed_device(session_provider)
    collection_id = uuid4()
    now = datetime.now(UTC)
    async with session_provider() as db:
        db.add(ContextCollection(
            id=collection_id, device_id=device.id, profile="inventory_v1", requested_by="scheduler",
            idempotency_key="expired-collecting", status="collecting",
            requested_at=now - timedelta(minutes=2), expires_at=now - timedelta(seconds=1),
        ))
        await db.commit()

    assert not await CommandService(session_provider).deliver_next(
        device.id, uuid4(), [].append, allowed_capabilities={"context.health.collect"},
    )
    async with session_provider() as db:
        collection = await db.get(ContextCollection, collection_id)
        assert collection is not None and collection.status == "expired"
