"""Idempotency and failure invariants for Device Context result ingestion."""

from sqlalchemy import func, select

from endpoint_server.context.models import ContextCurrent, ContextSnapshot
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
