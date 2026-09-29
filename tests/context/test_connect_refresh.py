"""Capability-aware refresh requests created when an agent connects."""

from datetime import UTC, datetime, timedelta
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


async def test_connect_refresh_replaces_expired_work_in_the_same_freshness_bucket(session) -> None:
    device = Device(id=uuid4(), device_identifier="connect-expired", display_name="Expired")
    session.add(device)
    await session.flush()
    capabilities = {"context.baseline.collect"}
    now = datetime(2026, 9, 18, 10, 0, tzinfo=UTC)
    assert await queue_connect_refreshes(session, device.id, capabilities, now=now) == 1
    old = await session.scalar(select(ContextCollection))

    renewed_at = now + timedelta(minutes=15)
    assert await queue_connect_refreshes(session, device.id, capabilities, now=renewed_at) == 1
    await session.refresh(old)
    assert old.status == "expired"
    assert old.failure_code == "collection_expired"
    active = (await session.scalars(select(ContextCollection).where(ContextCollection.status == "requested"))).all()
    assert len(active) == 1
    assert active[0].id != old.id
    assert active[0].expires_at.replace(tzinfo=UTC) == renewed_at + timedelta(minutes=15)
    assert await queue_connect_refreshes(session, device.id, capabilities, now=renewed_at) == 0
