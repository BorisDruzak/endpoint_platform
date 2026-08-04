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
