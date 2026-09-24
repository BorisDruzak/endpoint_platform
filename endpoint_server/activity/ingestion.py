"""Persist bounded activity changes independently of command results."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_contracts.activity import ActivityObservationV1, ActivitySectionsV1
from endpoint_contracts.context import DeviceContextActivityV1, DeviceContextEnvelopeV1
from endpoint_contracts.endpoint_policy import EndpointPolicyV1
from endpoint_server.context.canonicalize import canonicalize_activity
from endpoint_server.context.ingestion import _advisory_lock, _advance_current_pointer
from endpoint_server.context.models import ContextCollection, ContextCurrent, ContextSnapshot
from endpoint_server.context.semantic_hash import semantic_hash
from endpoint_server.context.service import ContextNotFound, ContextValidationError
from endpoint_server.db.models import Device
from endpoint_server.policy.models import PolicyDeviceState
from endpoint_server.policy.service import resolve_effective_policy


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ContextValidationError("activity timestamp must be timezone-aware")
    return value.astimezone(UTC)


def _stored_utc(value: datetime) -> datetime:
    """SQLite drops timezone information; PostgreSQL preserves it."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


async def ingest_activity_observation(
    session: AsyncSession,
    device_id: UUID,
    observation: ActivityObservationV1,
    *,
    idle_threshold_seconds: int,
    received_at: datetime | None = None,
) -> ContextSnapshot | None:
    """Return a new snapshot only for a material change; always refresh current."""
    if isinstance(idle_threshold_seconds, bool) or not 60 <= idle_threshold_seconds <= 3600:
        raise ContextValidationError("activity idle threshold is outside policy bounds")
    when = _utc(received_at or datetime.now(UTC))
    observed_at = _utc(observation.observed_at)
    if observed_at > when + timedelta(minutes=5) or observed_at < when - timedelta(hours=24):
        raise ContextValidationError("activity observation time is outside live bounds")
    await _advisory_lock(session, f"context.current:{device_id}:activity_v1")
    device = await session.scalar(select(Device.id).where(Device.id == device_id))
    if device is None:
        raise ContextNotFound("device was not found")
    current = await session.scalar(select(ContextCurrent).where(
        ContextCurrent.device_id == device_id, ContextCurrent.profile == "activity_v1",
    ).with_for_update())
    current_snapshot = await session.get(ContextSnapshot, current.snapshot_id) if current else None
    if current is not None and current_snapshot is None:
        raise ContextValidationError("current activity snapshot is missing")
    latest_at = _stored_utc(current_snapshot.collected_at) if current_snapshot is not None else None
    if current is not None and current.last_projection is not None:
        try:
            latest_projection = DeviceContextEnvelopeV1.model_validate(current.last_projection)
        except Exception as error:
            raise ContextValidationError("current activity projection is invalid") from error
        if latest_projection.profile != "activity_v1":
            raise ContextValidationError("current activity projection has wrong profile")
        latest_at = _utc(latest_projection.collected_at)
    if latest_at is not None and observed_at <= latest_at:
        # Replayed or delayed samples may not roll back the current session.
        if latest_at == observed_at:
            last = _stored_utc(current.last_observed_at or current.updated_at)
            if when > last:
                current.last_observed_at = when
        await session.flush()
        return None
    state = observation.session_state
    if state in {"ACTIVE", "IDLE"}:
        state = "IDLE" if observation.idle_seconds >= idle_threshold_seconds else "ACTIVE"
    sections = ActivitySectionsV1(
        user_login=observation.user_login,
        session_state=state,
        idle_seconds=observation.idle_seconds,
        foreground=observation.foreground,
        browser=observation.browser,
    )
    envelope = DeviceContextActivityV1(
        schema_version="device_context_v1",
        profile="activity_v1",
        collected_at=observed_at,
        sections=sections,
    )
    projection = envelope.model_dump(mode="json")
    digest = semantic_hash(canonicalize_activity(projection))
    if current_snapshot is not None and current_snapshot.semantic_hash == digest:
        current.last_projection = projection
        if when > _stored_utc(current.last_observed_at or current.updated_at):
            current.last_observed_at = when
        await session.flush()
        return None
    existing = await session.scalar(select(ContextCollection).where(
        ContextCollection.device_id == device_id,
        ContextCollection.profile == "activity_v1",
        ContextCollection.requested_by == "activity-sensor",
        ContextCollection.idempotency_key == str(observation.observation_id),
    ).with_for_update())
    if existing is not None:
        # One observation identifier cannot create two immutable snapshots.
        return None
    collection = ContextCollection(
        id=uuid4(), device_id=device_id, profile="activity_v1",
        requested_by="activity-sensor", idempotency_key=str(observation.observation_id),
        status="completed", requested_at=when, result_received_at=when,
        validated_at=when, completed_at=when,
    )
    snapshot = ContextSnapshot(
        id=uuid4(), collection_id=collection.id, device_id=device_id,
        profile="activity_v1", collected_at=observed_at,
        semantic_hash=digest, raw_payload=None, normalized_projection=projection,
    )
    session.add_all((collection, snapshot))
    await session.flush()
    await _advance_current_pointer(session, snapshot, updated_at=when, lock_held=True)
    current = await session.scalar(select(ContextCurrent).where(
        ContextCurrent.device_id == device_id, ContextCurrent.profile == "activity_v1",
    ).with_for_update())
    if current is not None:
        current.last_projection = projection
    await session.flush()
    return snapshot


async def ingest_gateway_activity(
    session: AsyncSession,
    device_id: UUID,
    observation: ActivityObservationV1,
) -> ContextSnapshot | None:
    """Accept continuous telemetry only for the effective applied Activity policy."""
    version = await resolve_effective_policy(session, device_id)
    state = await session.scalar(select(PolicyDeviceState).where(PolicyDeviceState.device_id == device_id))
    if (
        version is None or state is None or state.status != "APPLIED"
        or state.policy_version_id != version.id or state.policy_digest != version.digest
    ):
        raise ContextValidationError("activity policy is not applied")
    policy = EndpointPolicyV1.model_validate(version.document)
    if not policy.activity.enabled:
        raise ContextValidationError("activity collection is disabled")
    if observation.foreground is not None and not policy.activity.foreground_application:
        raise ContextValidationError("foreground collection is disabled")
    if observation.browser is not None and not policy.activity.browser_context:
        raise ContextValidationError("browser context collection is disabled")
    return await ingest_activity_observation(
        session, device_id, observation,
        idle_threshold_seconds=policy.activity.idle_threshold_seconds,
    )


__all__ = ["ingest_activity_observation", "ingest_gateway_activity"]
