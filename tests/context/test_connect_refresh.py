"""Capability-aware refresh requests created when an agent connects."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import event, select

from endpoint_server.context.connect_refresh import queue_connect_refreshes
from endpoint_server.context.models import ContextCollection, ContextSnapshot
from endpoint_server.db.models import Device

from .test_collection_lifecycle import session


async def test_connect_refresh_without_supported_profiles_never_queries(session):
    statements = []

    def observe(_connection, _cursor, statement, *_):
        statements.append(statement)

    engine = session.get_bind()
    event.listen(engine, "before_cursor_execute", observe)
    try:
        assert await queue_connect_refreshes(session, uuid4(), {"context.health.collect"}) == 0
    finally:
        event.remove(engine, "before_cursor_execute", observe)
    assert statements == []


@pytest.mark.parametrize("seconds_inside_window", [0, 1])
async def test_connect_refresh_reads_pending_work_and_snapshot_together(session, seconds_inside_window):
    now = datetime(2026, 9, 18, 10, 0, tzinfo=UTC)
    observed_at = now - timedelta(minutes=15) + timedelta(seconds=seconds_inside_window)
    device = Device(device_identifier="connect-freshness-boundary")
    session.add(device)
    await session.flush()
    collection = ContextCollection(
        device_id=device.id, profile="network_v1", requested_by="operator",
        idempotency_key="existing-network", status="completed", requested_at=observed_at,
    )
    session.add(collection)
    await session.flush()
    session.add(ContextSnapshot(
        collection_id=collection.id, device_id=device.id, profile="network_v1",
        collected_at=observed_at, normalized_projection={},
    ))
    await session.commit()
    statements = []

    def observe(_connection, _cursor, statement, *_):
        if "ORDER BY context_snapshots.collected_at" in statement:
            statements.append(statement)

    engine = session.get_bind()
    event.listen(engine, "before_cursor_execute", observe)
    try:
        created = await queue_connect_refreshes(session, device.id, {"context.network.collect"}, now=now)
    finally:
        event.remove(engine, "before_cursor_execute", observe)
    assert created == (0 if seconds_inside_window else 1)
    assert len(statements) == 1 and "FROM context_collections" in statements[0]


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
