"""Validated, idempotent ingestion of Device Context command results."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_contracts import AgentResultV1, DeviceContextEnvelopeV1, validate_context_result_item
from endpoint_server.db.models import Command, CommandResult

from .canonicalize import canonicalize_baseline
from .diff import compare_snapshots
from .models import ContextCollection, ContextCurrent, ContextDiff, ContextSnapshot
from .semantic_hash import semantic_hash
from .service import ContextConflict, ContextNotFound, ContextValidationError, require_profile, require_uuid


_CAPABILITY_PROFILES = {
    "context.baseline.collect": "baseline_v1",
    "context.health.collect": "health_v1",
    "context.network.collect": "network_v1",
    "context.diagnostic.collect": "diagnostic_v1",
}
_TERMINAL_FAILURES = {"failed", "canceled", "expired"}


def _now(value: datetime | None = None) -> datetime:
    timestamp = value or datetime.now(UTC)
    if timestamp.tzinfo is None:
        raise ContextValidationError("timestamp must be timezone-aware")
    return timestamp.astimezone(UTC)


async def _advisory_lock(session: AsyncSession, key: str) -> None:
    if session.get_bind().dialect.name == "postgresql":
        await session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"), {"key": key})


def _result(value: AgentResultV1 | Mapping[str, object]) -> AgentResultV1:
    try:
        return value if isinstance(value, AgentResultV1) else AgentResultV1.model_validate(value)
    except ValidationError as error:
        raise ContextValidationError("invalid agent result") from error


def _success_envelope(result: AgentResultV1) -> DeviceContextEnvelopeV1:
    if result.status != "succeeded" or len(result.result_items) != 1:
        raise ContextValidationError("successful context result must contain exactly one envelope")
    try:
        return validate_context_result_item(result.result_items[0])
    except ValidationError as error:
        raise ContextValidationError("invalid device context envelope") from error


def _profile_for_failed_command(command: Command) -> str:
    profile = _CAPABILITY_PROFILES.get(command.command_kind)
    if profile is None:
        raise ContextValidationError("command is not a device context capability")
    return profile


async def _current_collection(
    session: AsyncSession, command: Command, result: CommandResult, profile: str
) -> ContextCollection:
    collection = await session.scalar(
        select(ContextCollection)
        .where(ContextCollection.command_result_id == result.id)
        .with_for_update()
    )
    if collection is not None:
        return collection
    collection = await session.scalar(
        select(ContextCollection)
        .where(ContextCollection.command_id == command.id)
        .with_for_update()
    )
    if collection is not None:
        if collection.profile != profile:
            raise ContextConflict("context command profile does not match collection")
        return collection
    collection = ContextCollection(
        id=uuid4(), device_id=command.device_id, profile=require_profile(profile),
        requested_by="agent-result", idempotency_key=f"result:{result.result_identifier}",
        command_id=command.id, status="result_received", requested_at=_now(result.completed_at),
    )
    session.add(collection)
    await session.flush()
    return collection


async def _advance_current_pointer(
    session: AsyncSession,
    snapshot: ContextSnapshot,
    *,
    updated_at: datetime,
    lock_held: bool = False,
) -> None:
    """Advance a device/profile pointer only for a strictly newer observation.

    The transaction-scoped advisory lock covers an absent current row, which a
    row lock alone cannot serialize. Equal timestamps intentionally preserve
    the first current snapshot so duplicate-time observations do not churn the
    pointer based on delayed completion order.
    """
    if not lock_held:
        await _advisory_lock(
            session, f"context.current:{snapshot.device_id}:{snapshot.profile}"
        )
    current = await session.scalar(
        select(ContextCurrent)
        .where(
            ContextCurrent.device_id == snapshot.device_id,
            ContextCurrent.profile == snapshot.profile,
        )
        .with_for_update()
    )
    if current is None:
        session.add(
            ContextCurrent(
                id=uuid4(),
                device_id=snapshot.device_id,
                profile=snapshot.profile,
                snapshot_id=snapshot.id,
                updated_at=updated_at,
            )
        )
        return

    current_snapshot = await session.scalar(
        select(ContextSnapshot)
        .where(ContextSnapshot.id == current.snapshot_id)
        .with_for_update()
    )
    if current_snapshot is None:
        raise ContextConflict("current context snapshot is missing")
    current_collected_at = current_snapshot.collected_at
    if current_collected_at.tzinfo is None:
        # SQLite drops tzinfo for DateTime(timezone=True); PostgreSQL preserves
        # it. Context snapshots are validated as UTC before persistence.
        current_collected_at = current_collected_at.replace(tzinfo=UTC)
    if snapshot.collected_at <= current_collected_at.astimezone(UTC):
        return
    current.snapshot_id = snapshot.id
    current.updated_at = updated_at


async def ingest_context_result(
    session: AsyncSession,
    command_result_id: UUID | str,
    result: AgentResultV1 | Mapping[str, object],
    *,
    now: datetime | None = None,
) -> ContextCollection:
    """Persist one command result exactly once; failed results never move current."""
    checked_result = _result(result)
    result_id = require_uuid(command_result_id, "command result id")
    await _advisory_lock(session, f"context.result:{result_id}")
    record = await session.scalar(select(CommandResult).where(CommandResult.id == result_id).with_for_update())
    if record is None:
        raise ContextNotFound("command result was not found")
    command = await session.scalar(select(Command).where(Command.id == record.command_id).with_for_update())
    if command is None:
        raise ContextNotFound("command for result was not found")
    if checked_result.command_id != command.id or checked_result.device_id != command.device_id:
        raise ContextValidationError("agent result does not match its command ownership")

    if checked_result.status == "succeeded":
        envelope = _success_envelope(checked_result)
        profile = envelope.profile
        expected_profile = _profile_for_failed_command(command)
        if profile != expected_profile:
            raise ContextValidationError("result profile does not match command capability")
    elif checked_result.status in _TERMINAL_FAILURES:
        envelope = None
        profile = _profile_for_failed_command(command)
    else:
        raise ContextValidationError("context result must be terminal")

    collection = await _current_collection(session, command, record, profile)
    if collection.command_result_id is not None:
        return collection
    observed_at = _now(now or checked_result.completed_at)
    raw_payload = checked_result.model_dump(mode="json")
    collection.command_result_id = record.id
    collection.result_received_at = observed_at
    collection.raw_result_payload = raw_payload

    if envelope is None:
        collection.status = "failed"
        collection.failed_at = observed_at
        collection.failure_code = f"command_{checked_result.status}"
        await session.flush()
        return collection

    collection.status = "validated"
    collection.validated_at = observed_at
    projection = envelope.model_dump(mode="json")
    baseline_hash = (
        semantic_hash(canonicalize_baseline(projection))
        if profile == "baseline_v1"
        else None
    )
    if baseline_hash is not None:
        # The same device/profile lock serializes the latest-hash check with
        # snapshot insertion; an absent current row is otherwise race-prone.
        await _advisory_lock(
            session, f"context.current:{command.device_id}:baseline_v1"
        )
        latest_baseline = await session.scalar(
            select(ContextSnapshot)
            .where(
                ContextSnapshot.device_id == command.device_id,
                ContextSnapshot.profile == "baseline_v1",
            )
            .order_by(ContextSnapshot.collected_at.desc(), ContextSnapshot.id.desc())
            .with_for_update()
        )
        if latest_baseline is not None and latest_baseline.semantic_hash == baseline_hash:
            collection.status = "completed"
            collection.completed_at = observed_at
            await session.flush()
            return collection
    snapshot = ContextSnapshot(
        id=uuid4(), collection_id=collection.id, device_id=command.device_id,
        profile=profile, collected_at=envelope.collected_at, semantic_hash=baseline_hash,
        raw_payload=raw_payload, normalized_projection=projection,
    )
    session.add(snapshot)
    await session.flush()
    if profile == "baseline_v1" and latest_baseline is not None:
        diff = compare_snapshots(latest_baseline.normalized_projection, projection)
        session.add(
            ContextDiff(
                id=uuid4(), device_id=command.device_id, profile=profile,
                before_snapshot_id=latest_baseline.id, after_snapshot_id=snapshot.id,
                diff_payload=diff.model_dump(mode="json"),
            )
        )
    await _advance_current_pointer(
        session,
        snapshot,
        updated_at=observed_at,
        lock_held=profile == "baseline_v1",
    )
    collection.status = "completed"
    collection.completed_at = observed_at
    await session.flush()
    return collection
