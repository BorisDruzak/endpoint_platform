"""Capability-aware refresh requests created when an agent connects."""

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select

from endpoint_server.context.connect_refresh import queue_connect_refreshes
from endpoint_server.context.models import ContextCollection
from endpoint_server.db.models import Device

from .test_collection_lifecycle import session


async def test_connect_refresh_queues_only_supported_inventory_profiles(session) -> None:
    device = Device(id=uuid4(), device_identifier="connect-device", display_name="Connect")
    session.add(device)
    await session.flush()

    created = await queue_connect_refreshes(
        session,
        device.id,
        {"context.baseline.collect", "context.inventory.collect", "context.network.collect"},
        now=datetime(2026, 9, 18, 10, 0, tzinfo=UTC),
    )

    queued = (await session.scalars(select(ContextCollection).order_by(ContextCollection.profile))).all()
    assert created == 3
    assert [collection.profile for collection in queued] == ["baseline_v1", "inventory_v1", "network_v1"]
    assert all(collection.requested_by == "connect-refresh" for collection in queued)


async def test_connect_refresh_does_not_duplicate_active_collection(session) -> None:
    device = Device(id=uuid4(), device_identifier="connect-replay", display_name="Replay")
    session.add(device)
    await session.flush()
    capabilities = {"context.baseline.collect", "context.inventory.collect", "context.network.collect"}
    now = datetime(2026, 9, 18, 10, 0, tzinfo=UTC)

    assert await queue_connect_refreshes(session, device.id, capabilities, now=now) == 3
    assert await queue_connect_refreshes(session, device.id, capabilities, now=now) == 0

    queued = (await session.scalars(select(ContextCollection))).all()
    assert len(queued) == 3
