"""Ordinary collection deadlines do not override terminal/operation ownership."""
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from endpoint_server.context.models import ContextCollection
from endpoint_server.context.repository import expire_overdue_collections
from endpoint_server.db.models import Device
from .test_collection_lifecycle import session


@pytest.mark.parametrize("status", ["result_received", "validated", "completed", "failed", "expired"])
async def test_expiry_preserves_received_results_and_terminal_collections(session, status):
    now = datetime.now(UTC)
    device = Device(id=uuid4(), device_identifier=f"expiry-{uuid4().hex}", display_name="Expiry")
    session.add(device)
    await session.flush()
    collection = ContextCollection(id=uuid4(), device_id=device.id, profile="baseline_v1",
        requested_by="test", idempotency_key="terminal", status=status,
        requested_at=now-timedelta(hours=2), expires_at=now-timedelta(hours=1))
    session.add(collection)
    await session.flush()
    await expire_overdue_collections(session, device.id, now=now)
    assert collection.status == status
    assert collection.failure_code is None


async def test_expiry_preserves_operation_owned_and_unbounded_requests(session):
    now = datetime.now(UTC)
    device = Device(id=uuid4(), device_identifier=f"expiry-{uuid4().hex}", display_name="Expiry")
    other = Device(id=uuid4(), device_identifier=f"other-{uuid4().hex}", display_name="Other")
    session.add_all([device, other])
    await session.flush()
    for key, owner, operation_id, deadline in [
        ("operation", device.id, uuid4(), now-timedelta(hours=1)),
        ("unbounded", device.id, None, None),
        ("future", device.id, None, now+timedelta(minutes=1)),
        ("other-device", other.id, None, now-timedelta(hours=1)),
    ]:
        session.add(ContextCollection(id=uuid4(), device_id=owner, profile="baseline_v1",
            requested_by="test", idempotency_key=key, status="requested", operation_id=operation_id,
            requested_at=now-timedelta(hours=2), expires_at=deadline))
    await session.flush()
    await expire_overdue_collections(session, device.id, now=now)
    collections=(await session.scalars(select(ContextCollection))).all()
    assert all(collection.status == "requested" for collection in collections)
