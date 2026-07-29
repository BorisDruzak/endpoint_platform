"""Transactional repository operations for Device Context collection ownership."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_server.db.models import Command, Device

from .models import ContextCollection
from .service import ContextConflict, ContextNotFound, ContextValidationError, require_profile, require_uuid


def _now(value: datetime | None = None) -> datetime:
    timestamp = value or datetime.now(UTC)
    if timestamp.tzinfo is None:
        raise ContextValidationError("timestamp must be timezone-aware")
    return timestamp.astimezone(UTC)


async def _advisory_lock(session: AsyncSession, key: str) -> None:
    if session.get_bind().dialect.name == "postgresql":
        await session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"), {"key": key})


async def request_collection(
    session: AsyncSession,
    device_id: UUID | str,
    profile: str,
    requested_by: str,
    idempotency_key: str,
    *,
    now: datetime | None = None,
) -> ContextCollection:
    """Create one requested collection, replaying its exact device/profile key."""
    checked_device_id = require_uuid(device_id, "device id")
    checked_profile = require_profile(profile)
    if not requested_by or len(requested_by) > 128 or not idempotency_key or len(idempotency_key) > 128:
        raise ContextValidationError("request identity must be bounded non-empty text")
    await _advisory_lock(session, f"context.request:{checked_device_id}:{checked_profile}:{idempotency_key}")
    device = await session.scalar(select(Device).where(Device.id == checked_device_id).with_for_update())
    if device is None:
        raise ContextNotFound("device was not found")
    existing = await session.scalar(
        select(ContextCollection)
        .where(
            ContextCollection.device_id == checked_device_id,
            ContextCollection.profile == checked_profile,
            ContextCollection.idempotency_key == idempotency_key,
        )
        .with_for_update()
    )
    if existing is not None:
        return existing
    collection = ContextCollection(
        id=uuid4(), device_id=checked_device_id, profile=checked_profile,
        requested_by=requested_by, idempotency_key=idempotency_key,
        status="requested", requested_at=_now(now),
    )
    session.add(collection)
    await session.flush()
    return collection


async def link_collection_command(
    session: AsyncSession, collection_id: UUID | str, command_id: UUID | str
) -> ContextCollection:
    """Bind a requested collection to one device-bound command before delivery."""
    collection = await session.scalar(
        select(ContextCollection).where(ContextCollection.id == require_uuid(collection_id, "collection id")).with_for_update()
    )
    command = await session.scalar(
        select(Command).where(Command.id == require_uuid(command_id, "command id")).with_for_update()
    )
    if collection is None or command is None:
        raise ContextNotFound("collection or command was not found")
    if collection.device_id != command.device_id:
        raise ContextConflict("context command belongs to another device")
    if collection.command_id not in (None, command.id):
        raise ContextConflict("collection is already linked to another command")
    collection.command_id = command.id
    return collection
