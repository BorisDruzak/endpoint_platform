from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from endpoint_contracts import AgentCommandAckV1, AgentResultV1
from endpoint_contracts.gateway_ws import CommandEnvelopeV1
from endpoint_server.context.models import ContextCollection
from endpoint_server.db.models import (
    AuditEvent,
    Command,
    CommandDelivery,
    CommandResult,
    DeviceInstance,
    DeviceSession,
)
from endpoint_server.gateway.command_service import CommandService, CommandStateRejected
from endpoint_server.gateway.connection_registry import (
    ConnectionRegistry,
    GatewayConnection,
)
from endpoint_server.gateway.presence_service import PresenceService

from .conftest import agent_hello, seed_device


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
async def test_unacknowledged_command_replays_but_running_command_does_not(
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
    assert await service.deliver_next(device.id, presence.session_id, replay.append)
    assert first[0].payload.command_id == replay[0].payload.command_id
    assert first[0].payload == replay[0].payload

    await service.record_ack(
        device_id=device.id,
        session_id=presence.session_id,
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
        device.id, presence.session_id, after_running.append
    )
    async with session_provider() as session:
        assert len((await session.scalars(select(Command))).all()) == 1
        assert len((await session.scalars(select(CommandDelivery))).all()) == 1


@pytest.mark.asyncio
async def test_terminal_result_is_idempotent_and_ack_advances_durable_sequence(
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
    conflicting = result.model_copy(update={"message": "changed terminal body"})

    with pytest.raises(CommandStateRejected, match="conflicts"):
        await service.record_result(
            device_id=device.id,
            device_instance_id=presence.device_instance_id,
            session_id=presence.session_id,
            result_sequence=7,
            result=conflicting,
        )

    assert first_ack.payload.result_sequence == 7
    assert duplicate_ack == first_ack
    async with session_provider() as session:
        assert len((await session.scalars(select(CommandResult))).all()) == 1
        instance = await session.get(DeviceInstance, presence.device_instance_id)
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
