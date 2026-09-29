from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from endpoint_contracts.gateway_ws import CommandEnvelopeV1
from endpoint_server.context.models import ContextCollection
from endpoint_server.db.models import Command, CommandDelivery, DeviceSession
from endpoint_server.gateway.command_service import CommandService

from .conftest import seed_device


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
