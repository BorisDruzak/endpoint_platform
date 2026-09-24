"""Idempotency and failure invariants for Device Context result ingestion."""

from datetime import timedelta

from sqlalchemy import func, select

from endpoint_server.context.models import ContextCurrent, ContextDiff, ContextSnapshot, DeviceEvent
from endpoint_server.context.ingestion import ingest_context_result

from .test_collection_lifecycle import _result, session


async def _snapshot_count(session, device_id):
    return await session.scalar(
        select(func.count()).select_from(ContextSnapshot).where(ContextSnapshot.device_id == device_id)
    )


async def test_duplicate_result_creates_one_snapshot(session) -> None:
    """Removing result correlation would let a replay create multiple snapshots."""
    result_record, result = await _result(session)

    first = await ingest_context_result(session, result_record.id, result)
    second = await ingest_context_result(session, result_record.id, result)

    assert first.id == second.id
    assert await _snapshot_count(session, first.device_id) == 1


async def test_equivalent_later_baseline_does_not_create_another_snapshot(session) -> None:
    """Persisting a timestamp-only baseline change would churn immutable history."""
    first_record, first_result = await _result(session)
    first = await ingest_context_result(session, first_record.id, first_result)
    later_record, later_result = await _result(
        session,
        device_id=first.device_id,
        collected_at=first_result.completed_at + timedelta(minutes=5),
    )
    later_result.result_items[0]["warnings"] = ["probe_unavailable"]

    later = await ingest_context_result(session, later_record.id, later_result)

    assert later.status == "completed"
    assert await _snapshot_count(session, first.device_id) == 1
    current = await session.scalar(select(ContextCurrent).where(ContextCurrent.device_id == first.device_id))
    assert current.last_observed_at.replace(tzinfo=first_result.completed_at.tzinfo) == later_result.completed_at


async def test_equivalent_later_inventory_does_not_create_another_snapshot(session) -> None:
    """Volatile inventory collection fields must not churn physical history."""
    first_record, first_result = await _result(session, profile="inventory_v1")
    first = await ingest_context_result(session, first_record.id, first_result)
    later_record, later_result = await _result(
        session,
        device_id=first.device_id,
        collected_at=first_result.completed_at + timedelta(hours=24),
        profile="inventory_v1",
    )
    later_result.result_items[0]["warnings"] = ["probe_unavailable"]

    later = await ingest_context_result(session, later_record.id, later_result)

    assert later.status == "completed"
    assert await _snapshot_count(session, first.device_id) == 1


async def test_changed_inventory_creates_a_fixed_code_diff(session) -> None:
    """Inventory changes must stay auditable without raw fact values in the diff."""
    first_record, first_result = await _result(session, profile="inventory_v1")
    first = await ingest_context_result(session, first_record.id, first_result)
    later_record, later_result = await _result(
        session,
        device_id=first.device_id,
        collected_at=first_result.completed_at + timedelta(hours=24),
        profile="inventory_v1",
    )
    later_result.result_items[0]["sections"]["memory"]["total_bytes"] = 2048

    await ingest_context_result(session, later_record.id, later_result)

    diff = await session.scalar(select(ContextDiff).where(ContextDiff.device_id == first.device_id))
    assert diff is not None
    assert diff.diff_payload["profile"] == "inventory_v1"
    assert [change["code"] for change in diff.diff_payload["changes"]] == ["RAM_CHANGED"]
    events = (await session.scalars(select(DeviceEvent).where(DeviceEvent.device_id == first.device_id))).all()
    assert [event.event_kind for event in events] == ["RAM_CHANGED"]
    old_snapshot = await session.scalar(select(ContextSnapshot).where(ContextSnapshot.collection_id == first.id))
    await session.delete(old_snapshot)
    await session.flush()
    assert (await session.scalar(select(DeviceEvent).where(DeviceEvent.device_id == first.device_id))).event_kind == "RAM_CHANGED"


async def test_session_dedup_updates_observation_and_emits_change(session) -> None:
    first_record, first_result = await _result(session, profile="session_v1")
    first_result.result_items[0]["sections"] = {"current_user_login": "ivanov", "interactive_session_present": True}
    first = await ingest_context_result(session, first_record.id, first_result)
    later_record, later_result = await _result(session, profile="session_v1", device_id=first.device_id,
        collected_at=first_result.completed_at + timedelta(minutes=5))
    later_result.result_items[0]["sections"] = {"current_user_login": "ivanov", "interactive_session_present": True}
    await ingest_context_result(session, later_record.id, later_result)
    assert await _snapshot_count(session, first.device_id) == 1
    current = await session.scalar(select(ContextCurrent).where(ContextCurrent.device_id == first.device_id))
    assert current.last_observed_at.replace(tzinfo=later_result.completed_at.tzinfo) == later_result.completed_at
    changed_record, changed_result = await _result(session, profile="session_v1", device_id=first.device_id,
        collected_at=first_result.completed_at + timedelta(minutes=10))
    changed_result.result_items[0]["sections"] = {"current_user_login": "petrov", "interactive_session_present": True}
    await ingest_context_result(session, changed_record.id, changed_result)
    assert await _snapshot_count(session, first.device_id) == 2
    assert (await session.scalar(select(DeviceEvent).where(DeviceEvent.device_id == first.device_id))).event_kind == "SESSION_USER_CHANGED"


async def test_network_order_is_ignored_but_route_change_is_recorded(session) -> None:
    first_record, first_result = await _result(session, profile="network_v1")
    network = {"default_route": {"interface": "eth0", "gateway": "10.0.0.1"},
        "interfaces": [{"name": "eth0", "addresses": ["10.0.0.2", "fe80::1"]},
                       {"name": "eth1", "addresses": ["192.168.1.2"]}]}
    first_result.result_items[0]["sections"] = network
    first = await ingest_context_result(session, first_record.id, first_result)
    second_record, second_result = await _result(session, profile="network_v1", device_id=first.device_id,
        collected_at=first_result.completed_at + timedelta(minutes=15))
    second_result.result_items[0]["sections"] = {"default_route": network["default_route"],
        "interfaces": [{"name": "eth1", "addresses": ["192.168.1.2"]},
                       {"name": "eth0", "addresses": ["fe80::1", "10.0.0.2"]}]}
    await ingest_context_result(session, second_record.id, second_result)
    assert await _snapshot_count(session, first.device_id) == 1
    third_record, third_result = await _result(session, profile="network_v1", device_id=first.device_id,
        collected_at=first_result.completed_at + timedelta(minutes=30))
    third_result.result_items[0]["sections"] = {**network,
        "default_route": {"interface": "eth0", "gateway": "10.0.0.254"}}
    await ingest_context_result(session, third_record.id, third_result)
    assert await _snapshot_count(session, first.device_id) == 2
    assert (await session.scalar(select(DeviceEvent).where(DeviceEvent.device_id == first.device_id))).event_kind == "NETWORK_CHANGED"


async def test_failed_result_never_replaces_existing_current_snapshot(session) -> None:
    """Treating any terminal result as current would hide the last valid context."""
    good_record, good_result = await _result(session)
    completed = await ingest_context_result(session, good_record.id, good_result)
    before = await session.scalar(select(ContextCurrent).where(ContextCurrent.device_id == completed.device_id))
    assert before is not None

    failed_record, failed_result = await _result(
        session, status="failed", device_id=completed.device_id
    )
    failed = await ingest_context_result(session, failed_record.id, failed_result)
    after = await session.scalar(select(ContextCurrent).where(ContextCurrent.device_id == completed.device_id))

    assert failed.status == "failed"
    assert after is not None
    assert after.snapshot_id == before.snapshot_id
