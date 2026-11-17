from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import MetaData, event, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from endpoint_contracts import AgentCommandAckV1, AgentHeartbeatV1, AgentResultV1
from endpoint_contracts.gateway_ws import CommandEnvelopeV1
from endpoint_server.context.models import ContextCollection
from endpoint_server.db.models import (
    AuditEvent,
    Command,
    CommandDelivery,
    CommandResult,
    Device,
    DeviceInstance,
    DeviceSession,
)
from endpoint_server.gateway.command_service import CommandService, CommandStateRejected, next_pending_command, wss_work_available
from endpoint_server.gateway.connection_registry import (
    ConnectionRegistry,
    GatewayConnection,
)
from endpoint_server.gateway.presence_service import PresenceService
from tests.server.test_update_postgresql import update_service_database_url, update_service_provider

from .conftest import _GATEWAY_TABLES, agent_hello, seed_device


class RecordingSocket:
    def __init__(self) -> None:
        self.sent: list[dict[str, object]] = []
        self.closed: list[int] = []

    async def send_json(self, message: dict[str, object]) -> None:
        self.sent.append(message)

    async def close(self, code: int) -> None:
        self.closed.append(code)


async def _open_session(
    session_provider: async_sessionmaker[AsyncSession],
    device_id,
    instance_id,
):
    from endpoint_contracts import AgentHelloV1

    return await PresenceService(session_provider).open_session(
        device_id=device_id,
        hello=AgentHelloV1.model_validate(
            agent_hello(device_id, instance_id=instance_id)
        ),
        source_address="192.168.101.20",
    )


@pytest.mark.asyncio
async def test_newer_session_replaces_old_registry_and_durable_presence(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    device = await seed_device(session_provider)
    instance_id = uuid4()
    old_presence = await _open_session(session_provider, device.id, instance_id)
    new_presence = await _open_session(session_provider, device.id, instance_id)
    old_socket = RecordingSocket()
    new_socket = RecordingSocket()
    registry = ConnectionRegistry(max_connections=2)

    await registry.register(
        GatewayConnection(device.id, old_presence.session_id, old_socket)
    )
    replaced = await registry.register(
        GatewayConnection(device.id, new_presence.session_id, new_socket)
    )

    assert replaced is not None
    assert old_socket.sent[0]["kind"] == "server_shutdown_notice"
    assert old_socket.sent[0]["payload"]["reason"] == "session_replaced"
    assert old_socket.closed == [4001]
    async with session_provider() as session:
        old = await session.get(DeviceSession, old_presence.session_id)
        new = await session.get(DeviceSession, new_presence.session_id)
        audits = (
            await session.scalars(
                select(AuditEvent).where(
                    AuditEvent.action == "gateway.session_replaced"
                )
            )
        ).all()
    assert old is not None and old.closed_at is not None
    assert new is not None and new.closed_at is None
    assert len(audits) == 1


@pytest.mark.asyncio
async def test_unacknowledged_command_replays_only_after_reconnect(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    device = await seed_device(session_provider)
    presence = await _open_session(session_provider, device.id, uuid4())
    now = datetime.now(UTC)
    async with session_provider() as session:
        session.add(
            ContextCollection(
                id=uuid4(), device_id=device.id, profile="baseline_v1",
                requested_by="gateway-test", idempotency_key="reconnect-command",
                status="requested", requested_at=now,
            )
        )
        await session.commit()
    service = CommandService(session_provider)
    first: list[CommandEnvelopeV1] = []
    replay: list[CommandEnvelopeV1] = []
    assert await service.deliver_next(device.id, presence.session_id, first.append)
    assert not await service.deliver_next(device.id, presence.session_id, replay.append)
    assert not replay

    reconnected = await _open_session(session_provider, device.id, presence.device_instance_id)
    assert await service.deliver_next(device.id, reconnected.session_id, replay.append)
    assert first[0].payload.command_id == replay[0].payload.command_id
    assert first[0].payload == replay[0].payload

    await service.record_ack(
        device_id=device.id,
        session_id=reconnected.session_id,
        acknowledgement=AgentCommandAckV1(
            schema_version="agent_command_ack_v1",
            command_id=first[0].payload.command_id,
            device_id=device.id,
            status="running",
            acknowledged_at=now + timedelta(seconds=1),
        ),
    )
    after_running: list[CommandEnvelopeV1] = []
    assert not await service.deliver_next(
        device.id, reconnected.session_id, after_running.append
    )
    async with session_provider() as session:
        assert len((await session.scalars(select(Command))).all()) == 1
        assert len((await session.scalars(select(CommandDelivery))).all()) == 1


@pytest.mark.asyncio
async def test_late_ack_for_terminal_command_does_not_close_live_session(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    device = await seed_device(session_provider)
    presence = await _open_session(session_provider, device.id, uuid4())
    command_id = uuid4()
    async with session_provider() as session:
        session.add(
            Command(
                id=command_id,
                command_identifier=f"command-{command_id.hex}",
                device_id=device.id,
                command_kind="context.health.collect",
                status="succeeded",
            )
        )
        session.add(
            CommandDelivery(
                id=uuid4(),
                command_id=command_id,
                device_session_id=presence.session_id,
                delivery_identifier=f"delivery-{command_id.hex}",
                status="acknowledged",
            )
        )
        await session.commit()

    await CommandService(session_provider).record_ack(
        device_id=device.id,
        session_id=presence.session_id,
        acknowledgement=AgentCommandAckV1(
            schema_version="agent_command_ack_v1",
            command_id=command_id,
            device_id=device.id,
            status="acknowledged",
            acknowledged_at=datetime.now(UTC),
        ),
    )


@pytest.mark.asyncio
async def test_replayed_terminal_result_with_changed_payload_is_acknowledged(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    device = await seed_device(session_provider)
    presence = await _open_session(session_provider, device.id, uuid4())
    now = datetime.now(UTC)
    command_id = uuid4()
    delivery_id = uuid4()
    async with session_provider() as session:
        session.add(
            Command(
                id=command_id,
                command_identifier=f"command-{command_id.hex}",
                device_id=device.id,
                command_kind="context.baseline.collect",
                status="running",
                expires_at=now + timedelta(minutes=5),
            )
        )
        await session.flush()
        session.add_all(
            (
                CommandDelivery(
                    id=delivery_id,
                    command_id=command_id,
                    device_session_id=presence.session_id,
                    delivery_identifier=f"delivery-{command_id.hex}",
                    status="running",
                    acknowledged_at=now,
                ),
                ContextCollection(
                    id=uuid4(), device_id=device.id, profile="baseline_v1",
                    requested_by="gateway-test", idempotency_key="result-command",
                    command_id=command_id, status="collecting", requested_at=now,
                ),
            )
        )
        await session.commit()
    result = AgentResultV1(
        schema_version="agent_result_v1",
        command_id=command_id,
        device_id=device.id,
        status="failed",
        result_items=[],
        message="safe failure",
        completed_at=now + timedelta(seconds=2),
    )
    service = CommandService(session_provider)

    first_ack = await service.record_result(
        device_id=device.id,
        device_instance_id=presence.device_instance_id,
        session_id=presence.session_id,
        result_sequence=7,
        result=result,
    )
    duplicate_ack = await service.record_result(
        device_id=device.id,
        device_instance_id=presence.device_instance_id,
        session_id=presence.session_id,
        result_sequence=7,
        result=result,
    )
    replayed = result.model_copy(
        update={
            "message": "same command replayed after collection schedule",
            "completed_at": now + timedelta(minutes=5),
        }
    )
    replayed_ack = await service.record_result(
        device_id=device.id,
        device_instance_id=presence.device_instance_id,
        session_id=presence.session_id,
        result_sequence=8,
        result=replayed,
    )

    assert first_ack.payload.result_sequence == 7
    assert duplicate_ack == first_ack
    assert replayed_ack.payload.result_sequence == 8
    async with session_provider() as session:
        stored_results = (await session.scalars(select(CommandResult))).all()
        assert len(stored_results) == 1
        assert stored_results[0].completed_at.replace(tzinfo=UTC) == result.completed_at
        assert stored_results[0].result_sequence == 7
        instance = await session.get(DeviceInstance, presence.device_instance_id)
        assert instance is not None and instance.last_result_sequence == 8


@pytest.mark.asyncio
async def test_new_result_after_wss_reconnect_accepts_lower_connection_sequence(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    """A fresh WSS connection restarts frame numbering without replaying a result."""
    device = await seed_device(session_provider)
    instance_id = uuid4()
    first_presence = await _open_session(session_provider, device.id, instance_id)
    now = datetime.now(UTC)
    first_command_id = uuid4()
    second_command_id = uuid4()
    service = CommandService(session_provider)

    async with session_provider() as session:
        session.add(
            Command(
                id=first_command_id,
                command_identifier=f"command-{first_command_id.hex}",
                device_id=device.id,
                command_kind="context.baseline.collect",
                status="running",
                expires_at=now + timedelta(minutes=5),
            )
        )
        await session.flush()
        session.add_all(
            (
                CommandDelivery(
                    id=uuid4(),
                    command_id=first_command_id,
                    device_session_id=first_presence.session_id,
                    delivery_identifier=f"delivery-{first_command_id.hex}",
                    status="running",
                    acknowledged_at=now,
                ),
                ContextCollection(
                    id=uuid4(),
                    device_id=device.id,
                    profile="baseline_v1",
                    requested_by="gateway-test",
                    idempotency_key="first-wss-result",
                    command_id=first_command_id,
                    status="collecting",
                    requested_at=now,
                ),
            )
        )
        await session.commit()

    await service.record_result(
        device_id=device.id,
        device_instance_id=first_presence.device_instance_id,
        session_id=first_presence.session_id,
        result_sequence=7,
        result=AgentResultV1(
            schema_version="agent_result_v1",
            command_id=first_command_id,
            device_id=device.id,
            status="failed",
            result_items=[],
            message="first terminal result",
            completed_at=now + timedelta(seconds=1),
        ),
    )
    second_presence = await _open_session(session_provider, device.id, instance_id)

    async with session_provider() as session:
        session.add(
            Command(
                id=second_command_id,
                command_identifier=f"command-{second_command_id.hex}",
                device_id=device.id,
                command_kind="context.health.collect",
                status="running",
                expires_at=now + timedelta(minutes=5),
            )
        )
        await session.flush()
        session.add_all(
            (
                CommandDelivery(
                    id=uuid4(),
                    command_id=second_command_id,
                    device_session_id=second_presence.session_id,
                    delivery_identifier=f"delivery-{second_command_id.hex}",
                    status="running",
                    acknowledged_at=now,
                ),
                ContextCollection(
                    id=uuid4(),
                    device_id=device.id,
                    profile="health_v1",
                    requested_by="gateway-test",
                    idempotency_key="second-wss-result",
                    command_id=second_command_id,
                    status="collecting",
                    requested_at=now,
                ),
            )
        )
        await session.commit()

    acknowledgement = await service.record_result(
        device_id=device.id,
        device_instance_id=second_presence.device_instance_id,
        session_id=second_presence.session_id,
        result_sequence=2,
        result=AgentResultV1(
            schema_version="agent_result_v1",
            command_id=second_command_id,
            device_id=device.id,
            status="failed",
            result_items=[],
            message="new result on the reconnected socket",
            completed_at=now + timedelta(seconds=2),
        ),
    )

    assert acknowledgement.payload.result_sequence == 2
    async with session_provider() as session:
        instance = await session.get(DeviceInstance, second_presence.device_instance_id)
        assert instance is not None and instance.last_result_sequence == 7


@pytest.mark.asyncio
async def test_identical_https_result_can_be_acknowledged_after_wss_reconnect(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    import httpx

    from endpoint_server.main import create_app

    from .conftest import VALID_TOKEN, gateway_settings

    device = await seed_device(session_provider)
    presence = await _open_session(session_provider, device.id, uuid4())
    now = datetime.now(UTC)
    command_id = uuid4()
    async with session_provider() as session:
        session.add(
            Command(
                id=command_id,
                command_identifier=f"command-{command_id.hex}",
                device_id=device.id,
                command_kind="context.baseline.collect",
                status="running",
                expires_at=now + timedelta(minutes=5),
            )
        )
        await session.flush()
        session.add(
            ContextCollection(
                id=uuid4(),
                device_id=device.id,
                profile="baseline_v1",
                requested_by="gateway-test",
                idempotency_key="https-wss-result",
                command_id=command_id,
                status="collecting",
                requested_at=now,
            )
        )
        await session.commit()
    result = AgentResultV1(
        schema_version="agent_result_v1",
        command_id=command_id,
        device_id=device.id,
        status="failed",
        result_items=[],
        message="same terminal result",
        completed_at=now + timedelta(seconds=1),
    )
    app = create_app(gateway_settings(), session_provider)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 12345)),
        base_url="https://endpoint.sosnadmin.local",
    ) as client:
        response = await client.post(
            f"/agent/v1/gateway/commands/{command_id}/results",
            headers={
                "Authorization": f"Bearer {VALID_TOKEN}",
                "X-Forwarded-For": "192.168.101.20",
            },
            json=result.model_dump(mode="json"),
        )
    assert response.status_code == 204

    acknowledgement = await CommandService(session_provider).record_result(
        device_id=device.id,
        device_instance_id=presence.device_instance_id,
        session_id=presence.session_id,
        result_sequence=9,
        result=result,
    )

    assert acknowledgement.payload.result_sequence == 9


@pytest.mark.asyncio
async def test_heartbeat_updates_server_presence_without_replacing_source_address(
    session_provider: async_sessionmaker[AsyncSession],
) -> None:
    from endpoint_contracts import AgentHeartbeatV1

    device = await seed_device(session_provider)
    presence = await _open_session(session_provider, device.id, uuid4())
    observed_at = datetime.now(UTC) + timedelta(seconds=30)
    await PresenceService(session_provider).record_heartbeat(
        device_id=device.id,
        session_id=presence.session_id,
        heartbeat=AgentHeartbeatV1(
            schema_version="agent_heartbeat_v1",
            device_id=device.id,
            platform="linux",
            agent_version="4.0.1",
            reported_at=observed_at - timedelta(days=1),
        ),
        observed_at=observed_at,
    )

    async with session_provider() as session:
        record = await session.get(DeviceSession, presence.session_id)
    assert record is not None
    assert record.source_address == "192.168.101.20"
    assert record.last_seen_at.replace(tzinfo=UTC) == observed_at


@pytest_asyncio.fixture(params=["sqlite", "postgresql"])
async def reconnect_provider(request, session_provider):
    if request.param == "sqlite":
        yield session_provider
        return

    url = os.getenv("ENDPOINT_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("set ENDPOINT_TEST_POSTGRES_URL to a disposable loopback PostgreSQL server")
    parsed = make_url(url)
    if parsed.host not in {"127.0.0.1", "localhost", "::1"} or parsed.query:
        pytest.fail("WSS concurrency tests require a disposable loopback PostgreSQL server")
    schema = f"gateway_reconnect_{uuid4().hex}"
    engine = create_async_engine(
        parsed.set(drivername="postgresql+asyncpg"),
        connect_args={"server_settings": {"search_path": schema, "lock_timeout": "3s"}},
    )
    tables = set()

    def add_table(table):
        if table not in tables:
            tables.add(table)
            for key in table.foreign_keys:
                add_table(key.column.table)

    for table in _GATEWAY_TABLES:
        add_table(table)
    # Creating cyclic PostgreSQL foreign keys via ALTER mutates their constraint objects.
    # Keep the shared model metadata intact for the SQLite fixtures in this process.
    metadata = MetaData(naming_convention=DeviceSession.metadata.naming_convention)
    for table in sorted(tables, key=lambda table: table.key):
        table.to_metadata(metadata)

    try:
        async with engine.begin() as db:
            await db.execute(text(f'CREATE SCHEMA "{schema}"'))
            await db.run_sync(metadata.create_all)
        yield async_sessionmaker(engine, expire_on_commit=False)
    finally:
        try:
            async with engine.begin() as db:
                await db.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        finally:
            await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("previous_already_closed", [False, True])
async def test_concurrent_handshake_preserves_database_owner(
    reconnect_provider, monkeypatch, reverse, previous_already_closed,
):
    session_provider = reconnect_provider
    import asyncio
    import json

    from endpoint_server.gateway.ws_routes import connect_agent
    from .conftest import FakeGatewaySocket

    device = await seed_device(session_provider)
    instance_id = uuid4()
    registry = ConnectionRegistry()
    first_committed = asyncio.Event()
    release = asyncio.Event()
    second_waiting = asyncio.Event()
    opens = []
    closes = []
    original_open = PresenceService.open_session
    original_close = PresenceService.close_session

    class ObservedLock(asyncio.Lock):
        async def acquire(self):
            if self.locked():
                second_waiting.set()
            return await super().acquire()

    lock = ObservedLock()
    monkeypatch.setattr(registry, "handshake_lock", lambda _: lock)

    async def paused_open(self, **kwargs):
        presence = await original_open(self, **kwargs)
        opens.append(presence)
        if len(opens) == 1:
            first_committed.set()
            await release.wait()
        return presence

    async def no_connect_refresh(*_args):
        return 0

    async def observe_close(self, **kwargs):
        closes.append(kwargs["session_id"])
        await original_close(self, **kwargs)

    monkeypatch.setattr("endpoint_server.gateway.ws_routes.queue_connect_refreshes", no_connect_refresh)
    monkeypatch.setattr(PresenceService, "open_session", paused_open)
    monkeypatch.setattr(PresenceService, "close_session", observe_close)

    class Socket(FakeGatewaySocket):
        def __post_init__(self):
            super().__post_init__()
            self.app.state.gateway_connection_registry = registry
            self.hello_sent = asyncio.Event()
            self.inbound = asyncio.Queue()
            self.closed = []

        async def accept(self):
            pass

        async def receive(self):
            return await self.inbound.get()

        async def send_json(self, message):
            if message["kind"] == "gateway_hello":
                self.hello_sent.set()

        async def close(self, code):
            self.closed.append(code)
            self.inbound.put_nowait({"type": "websocket.disconnect"})

    sockets = [Socket(session_provider), Socket(session_provider)]
    first, second = sockets[::-1] if reverse else sockets
    hello = agent_hello(device.id, instance_id=instance_id)
    hello["capabilities"] = []
    envelope = {
        "schema_version": "gateway_ws_envelope_v1",
        "kind": "agent_hello", "sequence": 0,
        "payload": hello,
    }
    first.inbound.put_nowait({"type": "websocket.receive", "text": json.dumps(envelope)})
    second.inbound.put_nowait({"type": "websocket.receive", "text": json.dumps(envelope)})
    tasks = [asyncio.create_task(connect_agent(first))]
    try:
        async with asyncio.timeout(6):
            await first_committed.wait()
            tasks.append(asyncio.create_task(connect_agent(second)))
            await second_waiting.wait()
            assert len(opens) == 1
            if previous_already_closed:
                await original_close(
                    PresenceService(session_provider),
                    device_id=device.id,
                    session_id=opens[0].session_id,
                    reason="another_transaction",
                )
            release.set()
            await second.hello_sent.wait()
            live = await registry.get(device.id)
            assert live.websocket is second and live.session_id == opens[1].session_id
            async with session_provider() as db:
                active = (await db.scalars(select(DeviceSession).where(
                    DeviceSession.device_id == device.id, DeviceSession.closed_at.is_(None),
                ))).all()
            assert [session.id for session in active] == [live.session_id]
            await tasks[0]
            assert first.closed == [4001] and not second.closed
            assert await registry.get(device.id) is live
    finally:
        release.set()
        for socket in sockets:
            socket.inbound.put_nowait({"type": "websocket.disconnect"})
        async with asyncio.timeout(5):
            await asyncio.gather(*tasks)
    expected_closes = opens if previous_already_closed else opens[1:]
    assert closes == [presence.session_id for presence in expected_closes]


@pytest.mark.asyncio
async def test_postgresql_heartbeat_and_handshake_lock_session_before_instance(reconnect_provider):
    import asyncio

    from sqlalchemy import event

    if reconnect_provider.kw["bind"].dialect.name != "postgresql":
        pytest.skip("row locking requires PostgreSQL")
    device = await seed_device(reconnect_provider)
    instance_id = uuid4()
    old = await _open_session(reconnect_provider, device.id, instance_id)
    presence = PresenceService(reconnect_provider)
    lock_order = []
    engine = reconnect_provider.kw["bind"]

    def record_locks(_connection, _cursor, statement, *_):
        if not statement.rstrip().endswith("FOR UPDATE"):
            return
        for table in ("device_sessions", "device_instances"):
            if f"FROM {table}" in statement:
                lock_order.append((asyncio.current_task().get_name(), table))

    event.listen(engine.sync_engine, "before_cursor_execute", record_locks)
    try:
        # Block heartbeat at its second lock. When it asks for the instance,
        # it already owns the session row, regardless of query send order.
        async with reconnect_provider() as db:
            await db.scalar(select(DeviceInstance).where(
                DeviceInstance.id == old.device_instance_id,
            ).with_for_update())
            heartbeat = asyncio.create_task(presence.record_heartbeat(
                device_id=device.id, session_id=old.session_id,
                work_available=wss_work_available(device.id, frozenset({"context.health.collect"})),
                heartbeat=AgentHeartbeatV1(
                    schema_version="agent_heartbeat_v1", device_id=device.id,
                    platform="linux", agent_version="4.0.0", reported_at=datetime.now(UTC),
                ),
            ), name="heartbeat")
            replacement = None
            try:
                async with asyncio.timeout(5):
                    while ("heartbeat", "device_instances") not in lock_order:
                        await asyncio.sleep(0.01)
                    replacement = asyncio.create_task(
                        _open_session(reconnect_provider, device.id, instance_id), name="handshake",
                    )
                    while ("handshake", "device_sessions") not in lock_order:
                        await asyncio.sleep(0.01)
                    await db.commit()
                    has_work, current = await asyncio.gather(heartbeat, replacement)
                    assert not has_work
            finally:
                if replacement is not None and not replacement.done():
                    replacement.cancel()
                if not heartbeat.done():
                    heartbeat.cancel()
                await asyncio.gather(*(task for task in (heartbeat, replacement) if task), return_exceptions=True)
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", record_locks)
    assert [table for task, table in lock_order if task == "heartbeat"] == [
        "device_sessions", "device_instances",
    ]
    assert [table for task, table in lock_order if task == "handshake"] == [
        "device_sessions", "device_instances",
    ]
    async with reconnect_provider() as db:
        replaced_session = await db.get(DeviceSession, old.session_id)
        active_session = await db.get(DeviceSession, current.session_id)
    assert replaced_session.closed_at is not None
    assert active_session.closed_at is None


@pytest.mark.asyncio
@pytest.mark.parametrize("message", ["start", "result"])
async def test_postgresql_replay_and_feedback_do_not_deadlock(update_service_provider, message):
    provider = update_service_provider
    device = await seed_device(provider, token=uuid4().hex)
    instance_id = uuid4()
    presence = await _open_session(provider, device.id, instance_id)
    now = datetime.now(UTC)
    collection_id = uuid4()
    async with provider() as session:
        session.add(ContextCollection(
            id=collection_id, device_id=device.id, profile="health_v1", requested_by="operator",
            idempotency_key="same-device-replay", status="requested", requested_at=now,
        ))
        await session.commit()

    service = CommandService(provider)
    assert await service.deliver_next(device.id, presence.session_id, lambda _: None)
    replacement = await _open_session(provider, device.id, instance_id)
    delivered = []
    assert await service.deliver_next(device.id, replacement.session_id, delivered.append)
    command_id = delivered[0].payload.command_id
    if message == "start":
        feedback = service.record_ack(
            device_id=device.id, session_id=replacement.session_id, start_permission=True,
            acknowledgement=AgentCommandAckV1(
                schema_version="agent_command_ack_v1", command_id=command_id,
                device_id=device.id, status="running", acknowledged_at=now,
            ),
        )
    else:
        feedback = service.record_result(
            device_id=device.id, device_instance_id=replacement.device_instance_id,
            session_id=replacement.session_id, result_sequence=1, durable_replay=True,
            result=AgentResultV1(
                schema_version="agent_result_v1", command_id=command_id, device_id=device.id,
                status="failed", result_items=[], message="collection failed", completed_at=now,
            ),
        )

    waiting = asyncio.Event()
    task = None
    engine = provider.engine.sync_engine

    def observe(_connection, _cursor, statement, *_):
        if asyncio.current_task() is task and statement.rstrip().endswith("FOR UPDATE"):
            if "FROM devices" in statement or "FROM context_collections" in statement:
                waiting.set()

    event.listen(engine, "before_cursor_execute", observe)
    try:
        async with asyncio.timeout(10):
            async with provider() as dispatch:
                # Pause the delivery transaction with its parent and collection
                # locks held, just before it tries to claim the existing command.
                await dispatch.scalar(select(Device.id).where(Device.id == device.id).with_for_update())
                await dispatch.scalar(
                    select(ContextCollection.id).where(ContextCollection.id == collection_id).with_for_update()
                )
                task = asyncio.create_task(feedback)
                await waiting.wait()
                replay = await next_pending_command(dispatch, device.id, transport="gateway_wss")
                assert replay.command_id == command_id
                await dispatch.commit()
            receipt = await task
    finally:
        event.remove(engine, "before_cursor_execute", observe)
        if task is not None:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        else:
            feedback.close()

    assert receipt.kind == ("command_start" if message == "start" else "result_ack")
    assert receipt.payload.command_id == command_id
    async with provider() as session:
        command = await session.get(Command, command_id)
        collection = await session.get(ContextCollection, collection_id)
        assert (command.status, collection.status) == (
            ("running", "collecting") if message == "start" else ("failed", "failed")
        )


@pytest.mark.asyncio
async def test_postgresql_start_waits_for_session_close(update_service_provider):
    provider = update_service_provider
    device = await seed_device(provider, token=uuid4().hex)
    presence = await _open_session(provider, device.id, uuid4())
    now = datetime.now(UTC)
    async with provider() as seed:
        seed.add(ContextCollection(
            device_id=device.id, profile="health_v1", requested_by="operator",
            idempotency_key="session-close-before-start", status="requested", requested_at=now,
        ))
        await seed.commit()

    service = CommandService(provider)
    sent = []
    assert await service.deliver_next(device.id, presence.session_id, sent.append)
    command_id = sent[0].payload.command_id
    acknowledgement = AgentCommandAckV1(
        schema_version="agent_command_ack_v1", command_id=command_id, device_id=device.id,
        status="running", acknowledged_at=now,
    )

    async with provider() as closing:
        session = await closing.get(DeviceSession, presence.session_id, with_for_update=True)
        session.closed_at = now
        await closing.flush()
        closing_pid = await closing.scalar(text("SELECT pg_backend_pid()"))

        task = asyncio.create_task(service.record_ack(
            device_id=device.id, session_id=presence.session_id,
            acknowledgement=acknowledgement, start_permission=True,
        ))
        try:
            async with asyncio.timeout(5), provider() as monitor:
                while True:
                    blocked = await monitor.scalar(text(
                        "SELECT EXISTS (SELECT 1 FROM pg_stat_activity "
                        "WHERE :closing_pid = ANY(pg_blocking_pids(pid)))"
                    ), {"closing_pid": closing_pid})
                    if blocked:
                        break
                    await monitor.rollback()
                    await asyncio.sleep(0.01)
                assert not task.done()
            await closing.commit()
            with pytest.raises(CommandStateRejected, match="command is unavailable"):
                await asyncio.wait_for(task, timeout=5)
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async with provider() as verify:
        command = await verify.get(Command, command_id)
        delivery = await verify.scalar(select(CommandDelivery).where(CommandDelivery.command_id == command_id))
        assert command.status == delivery.status == "delivered"
        assert delivery.acknowledged_at is None
