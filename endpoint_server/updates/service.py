"""Audited immutable-build and update-rollout domain service."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import and_, or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_contracts import (
    AgentUpdateAcknowledgementV1,
    AgentUpdateRecommendationV1,
    AgentUpdateReportV1,
    UpdateBuildManifestV1,
    UpdateRolloutCreateV1,
)
from endpoint_contracts.update_safety import (
    validate_no_opaque_update_secret,
    validate_public_update_prose,
)
from endpoint_server.audit.service import append_audit_event
from endpoint_server.db.models import (
    Device,
    UpdateBuild,
    UpdateReport,
    UpdateRollout,
    UpdateTarget,
)

from .errors import (
    UpdateConflict,
    UpdateNotFound,
    UpdateStateError,
    UpdateValidationError,
)


_ACTIVE_TARGET_STATUSES = ("assigned", "requested", "scheduled")
_TERMINAL_TARGET_STATUSES = ("applied", "failed", "rolled_back", "cancelled")
_PLATFORMS = ("linux_amd64", "windows_amd64")
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _timestamp(value: datetime | None) -> datetime:
    checked = value or datetime.now(UTC)
    if checked.tzinfo is None:
        raise UpdateValidationError("timestamp must be timezone-aware")
    return checked.astimezone(UTC)


def _request_id(value: str) -> str:
    if not isinstance(value, str) or not _SAFE_IDENTIFIER.fullmatch(value):
        raise UpdateValidationError("request id must be an opaque safe identifier")
    return value


def _actor_identifier(actor: object) -> str:
    candidate: object = actor
    user = getattr(actor, "user", None)
    if user is not None:
        candidate = getattr(user, "id", None)
    elif not isinstance(actor, (str, UUID)):
        candidate = getattr(actor, "id", None)
    value = str(candidate) if candidate is not None else ""
    if not _SAFE_IDENTIFIER.fullmatch(value):
        raise UpdateValidationError("actor must have a bounded identifier")
    return value


def _safe_reason(value: str | None, *, required: bool = False) -> str | None:
    """Apply the service-only public-reason persistence safety boundary."""
    try:
        return validate_public_update_prose(
            value,
            field_name="reason",
            max_length=512,
            required=required,
        )
    except ValueError as error:
        raise UpdateValidationError("reason must be bounded safe text") from error


def _uuid(value: UUID | str, name: str) -> UUID:
    try:
        return value if isinstance(value, UUID) else UUID(value)
    except (TypeError, ValueError, AttributeError) as error:
        raise UpdateValidationError(f"{name} must be a UUID") from error


def _manifest(
    value: UpdateBuildManifestV1 | Mapping[str, object],
) -> UpdateBuildManifestV1:
    try:
        return (
            value
            if isinstance(value, UpdateBuildManifestV1)
            else UpdateBuildManifestV1.model_validate(value)
        )
    except ValidationError as error:
        raise UpdateValidationError("invalid immutable build manifest") from error


def _acknowledgement(
    value: AgentUpdateAcknowledgementV1 | Mapping[str, object],
) -> AgentUpdateAcknowledgementV1:
    try:
        return (
            value
            if isinstance(value, AgentUpdateAcknowledgementV1)
            else AgentUpdateAcknowledgementV1.model_validate(value)
        )
    except ValidationError as error:
        raise UpdateValidationError("invalid update acknowledgement") from error


def _report(
    value: AgentUpdateReportV1 | Mapping[str, object],
) -> AgentUpdateReportV1:
    try:
        validated = AgentUpdateReportV1.model_validate(
            value.model_dump() if isinstance(value, AgentUpdateReportV1) else value
        )
        validate_no_opaque_update_secret(validated.report_key, field_name="report key")
        validate_no_opaque_update_secret(
            validated.reported_version,
            field_name="reported version",
        )
        return validated
    except (ValidationError, ValueError) as error:
        raise UpdateValidationError("invalid update report") from error


def _build_values(manifest: UpdateBuildManifestV1) -> dict[str, object]:
    try:
        release_notes = validate_public_update_prose(
            manifest.release_notes,
            field_name="release notes",
            max_length=4096,
            allow_newlines=True,
        )
    except ValueError as error:
        raise UpdateValidationError(
            "release notes must be bounded safe text"
        ) from error
    return {
        "build_identifier": manifest.build_identifier,
        "version": manifest.version,
        "platform": manifest.platform,
        "channel": manifest.channel,
        "artifact_identifier": manifest.artifact_name,
        "artifact_url": str(manifest.artifact_url),
        "artifact_name": manifest.artifact_name,
        "archive_type": manifest.archive_type,
        "sha256_digest": manifest.sha256,
        "size": manifest.size,
        "release_notes": release_notes,
    }


def _same_manifest(build: UpdateBuild, values: Mapping[str, object]) -> bool:
    return all(getattr(build, field) == value for field, value in values.items())


async def _postgresql_advisory_lock(session: AsyncSession, key: str) -> None:
    bind = session.get_bind()
    if bind.dialect.name == "postgresql":
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
            {"key": key},
        )


async def register_build(
    session: AsyncSession,
    manifest: UpdateBuildManifestV1 | Mapping[str, object],
    actor: object,
    request_id: str,
    *,
    now: datetime | None = None,
) -> UpdateBuild:
    """Register one immutable manifest, returning an exact replay idempotently."""
    validated = _manifest(manifest)
    actor_id = _actor_identifier(actor)
    correlation_id = _request_id(request_id)
    occurred_at = _timestamp(now)
    values = _build_values(validated)
    identity_lock = (
        f"updates.build:{validated.platform}:{validated.channel}:{validated.version}:"
        f"{validated.build_identifier}"
    )
    await _postgresql_advisory_lock(session, identity_lock)
    existing = (
        await session.scalars(
            select(UpdateBuild)
            .where(
                or_(
                    UpdateBuild.build_identifier == validated.build_identifier,
                    and_(
                        UpdateBuild.platform == validated.platform,
                        UpdateBuild.channel == validated.channel,
                        UpdateBuild.version == validated.version,
                    ),
                )
            )
            .with_for_update()
        )
    ).all()
    if existing:
        if len(existing) == 1 and _same_manifest(existing[0], values):
            return existing[0]
        raise UpdateConflict("build identity already owns a different manifest")

    build = UpdateBuild(id=uuid4(), **values)
    session.add(build)
    await append_audit_event(
        session,
        actor_kind="admin",
        actor_identifier=actor_id,
        action="updates.build_registered",
        object_kind="update_build",
        object_identifier=str(build.id),
        request_id=correlation_id,
        details={
            "build_identifier": build.build_identifier,
            "channel": build.channel,
            "platform": build.platform,
            "version": build.version,
        },
        occurred_at=occurred_at,
    )
    try:
        await session.flush()
    except IntegrityError as error:
        raise UpdateConflict("build identity is already registered") from error
    return build


async def _locked_build(session: AsyncSession, build_id: UUID | str) -> UpdateBuild:
    build = await session.scalar(
        select(UpdateBuild)
        .where(UpdateBuild.id == _uuid(build_id, "build id"))
        .with_for_update()
    )
    if build is None:
        raise UpdateNotFound("update build not found")
    return build


async def _locked_rollout(
    session: AsyncSession, rollout_id: UUID | str
) -> UpdateRollout:
    rollout = await session.scalar(
        select(UpdateRollout)
        .where(UpdateRollout.id == _uuid(rollout_id, "rollout id"))
        .with_for_update()
    )
    if rollout is None:
        raise UpdateNotFound("update rollout not found")
    return rollout


async def _validate_rollout_input(
    build: UpdateBuild,
    mode: str,
    device_ids: Sequence[UUID | str],
    reason: str | None,
) -> tuple[list[UUID], str | None]:
    normalized_reason = _safe_reason(reason, required=mode == "rollback")
    try:
        contract = UpdateRolloutCreateV1.model_validate(
            {
                "schema_version": "update_rollout_v1",
                "build_identifier": build.build_identifier,
                "mode": mode,
                "device_ids": [
                    _uuid(device_id, "device id") for device_id in device_ids
                ],
                "reason": normalized_reason,
            }
        )
    except ValidationError as error:
        raise UpdateValidationError("invalid update rollout") from error
    return list(contract.device_ids), contract.reason


async def _lock_assignable_devices(
    session: AsyncSession,
    device_ids: Sequence[UUID],
    *,
    excluding_rollout_id: UUID | None = None,
) -> None:
    devices = (
        await session.scalars(
            select(Device)
            .where(Device.id.in_(device_ids), Device.retired_at.is_(None))
            .order_by(Device.id)
            .with_for_update()
        )
    ).all()
    if len(devices) != len(device_ids):
        raise UpdateNotFound("one or more update devices were not found")
    ownership_query = select(UpdateTarget).where(
        UpdateTarget.device_id.in_(device_ids),
        UpdateTarget.status.in_(_ACTIVE_TARGET_STATUSES),
    )
    if excluding_rollout_id is not None:
        ownership_query = ownership_query.where(
            UpdateTarget.rollout_id != excluding_rollout_id
        )
    owned = (
        await session.scalars(
            ownership_query.order_by(UpdateTarget.device_id).with_for_update()
        )
    ).all()
    if owned:
        raise UpdateConflict("one or more devices already have an active update")


async def _require_completed_canary(session: AsyncSession, build_id: UUID) -> None:
    canary = await session.scalar(
        select(UpdateRollout)
        .where(
            UpdateRollout.build_id == build_id,
            UpdateRollout.mode == "canary",
            UpdateRollout.status == "completed",
        )
        .order_by(UpdateRollout.completed_at.desc(), UpdateRollout.id)
        .limit(1)
        .with_for_update()
    )
    if canary is None:
        raise UpdateStateError("bulk rollout requires a completed canary")


async def _create_active_rollout(
    session: AsyncSession,
    build: UpdateBuild,
    mode: str,
    device_ids: Sequence[UUID],
    reason: str | None,
    *,
    actor_id: str,
    request_id: str,
    now: datetime,
) -> UpdateRollout:
    await _lock_assignable_devices(session, device_ids)
    rollout = UpdateRollout(
        id=uuid4(),
        rollout_identifier=f"ur_{uuid4().hex}",
        build_id=build.id,
        mode=mode,
        reason=reason,
        status="active",
        started_at=now,
        paused_at=None,
        completed_at=None,
        cancelled_at=None,
    )
    session.add(rollout)
    await append_audit_event(
        session,
        actor_kind="admin",
        actor_identifier=actor_id,
        action="updates.rollout_created",
        object_kind="update_rollout",
        object_identifier=str(rollout.id),
        request_id=request_id,
        details={
            "build_identifier": build.build_identifier,
            "mode": mode,
            "reason": reason,
            "status": "active",
            "target_count": len(device_ids),
        },
        occurred_at=now,
    )
    for device_id in device_ids:
        target = UpdateTarget(
            id=uuid4(),
            rollout_id=rollout.id,
            device_id=device_id,
            target_identifier=f"ut_{uuid4().hex}",
            operation_id=str(uuid4()),
            status="assigned",
            assigned_at=now,
            requested_at=None,
            scheduled_at=None,
            terminal_at=None,
            safe_reason=reason,
            updated_at=now,
        )
        session.add(target)
        await append_audit_event(
            session,
            actor_kind="admin",
            actor_identifier=actor_id,
            action="updates.target_assigned",
            object_kind="update_target",
            object_identifier=str(target.id),
            request_id=request_id,
            details={
                "device_id": device_id,
                "rollout_identifier": rollout.rollout_identifier,
                "status": "assigned",
            },
            occurred_at=now,
        )
    try:
        await session.flush()
    except IntegrityError as error:
        raise UpdateConflict("an update target is already active") from error
    return rollout


async def create_rollout(
    session: AsyncSession,
    build_id: UUID | str,
    mode: str,
    device_ids: Sequence[UUID | str],
    reason: str | None,
    actor: object,
    request_id: str,
    *,
    now: datetime | None = None,
) -> UpdateRollout:
    """Create one active canary or bulk rollout and its explicit targets."""
    if mode == "rollback":
        raise UpdateStateError("rollback must name a triggering rollout")
    build = await _locked_build(session, build_id)
    normalized_ids, normalized_reason = await _validate_rollout_input(
        build,
        mode,
        device_ids,
        reason,
    )
    if mode == "bulk":
        await _require_completed_canary(session, build.id)
    return await _create_active_rollout(
        session,
        build,
        mode,
        normalized_ids,
        normalized_reason,
        actor_id=_actor_identifier(actor),
        request_id=_request_id(request_id),
        now=_timestamp(now),
    )


async def activate_rollout(
    session: AsyncSession,
    rollout_id: UUID | str,
    actor: object,
    request_id: str,
    *,
    now: datetime | None = None,
) -> UpdateRollout:
    """Resume one paused rollout without changing its immutable target set."""
    rollout = await _locked_rollout(session, rollout_id)
    if rollout.status == "active":
        return rollout
    if rollout.status != "paused":
        raise UpdateStateError("rollout cannot be activated from its current state")
    device_ids = (
        await session.scalars(
            select(UpdateTarget.device_id)
            .where(
                UpdateTarget.rollout_id == rollout.id,
                UpdateTarget.status.in_(_ACTIVE_TARGET_STATUSES),
            )
            .order_by(UpdateTarget.device_id)
        )
    ).all()
    if not device_ids:
        raise UpdateStateError("rollout has no resumable targets")
    await _lock_assignable_devices(
        session,
        device_ids,
        excluding_rollout_id=rollout.id,
    )
    targets = (
        await session.scalars(
            select(UpdateTarget)
            .where(UpdateTarget.rollout_id == rollout.id)
            .order_by(UpdateTarget.device_id)
            .with_for_update()
        )
    ).all()
    active_targets = [
        target for target in targets if target.status in _ACTIVE_TARGET_STATUSES
    ]
    if [target.device_id for target in active_targets] != list(device_ids):
        raise UpdateStateError("rollout has no resumable targets")
    occurred_at = _timestamp(now)
    rollout.status = "active"
    rollout.started_at = rollout.started_at or occurred_at
    rollout.paused_at = None
    await append_audit_event(
        session,
        actor_kind="admin",
        actor_identifier=_actor_identifier(actor),
        action="updates.rollout_activated",
        object_kind="update_rollout",
        object_identifier=str(rollout.id),
        request_id=_request_id(request_id),
        details={"status": "active"},
        occurred_at=occurred_at,
    )
    await session.flush()
    return rollout


async def pause_rollout(
    session: AsyncSession,
    rollout_id: UUID | str,
    actor: object,
    request_id: str,
    *,
    now: datetime | None = None,
) -> UpdateRollout:
    """Pause recommendations without releasing target ownership."""
    rollout = await _locked_rollout(session, rollout_id)
    if rollout.status == "paused":
        return rollout
    if rollout.status != "active":
        raise UpdateStateError("only an active rollout can be paused")
    occurred_at = _timestamp(now)
    rollout.status = "paused"
    rollout.paused_at = occurred_at
    await append_audit_event(
        session,
        actor_kind="admin",
        actor_identifier=_actor_identifier(actor),
        action="updates.rollout_paused",
        object_kind="update_rollout",
        object_identifier=str(rollout.id),
        request_id=_request_id(request_id),
        details={"status": "paused"},
        occurred_at=occurred_at,
    )
    await session.flush()
    return rollout


async def complete_rollout(
    session: AsyncSession,
    rollout_id: UUID | str,
    actor: object,
    request_id: str,
    *,
    now: datetime | None = None,
) -> UpdateRollout:
    """Complete a rollout only after every target is terminal."""
    rollout = await _locked_rollout(session, rollout_id)
    if rollout.status == "completed":
        return rollout
    if rollout.status not in {"active", "paused"}:
        raise UpdateStateError("rollout cannot be completed from its current state")
    targets = (
        await session.scalars(
            select(UpdateTarget)
            .where(UpdateTarget.rollout_id == rollout.id)
            .order_by(UpdateTarget.id)
            .with_for_update()
        )
    ).all()
    if not targets or any(
        target.status not in _TERMINAL_TARGET_STATUSES for target in targets
    ):
        raise UpdateStateError("all rollout targets must be terminal")
    occurred_at = _timestamp(now)
    rollout.status = "completed"
    rollout.completed_at = occurred_at
    rollout.paused_at = None
    await append_audit_event(
        session,
        actor_kind="admin",
        actor_identifier=_actor_identifier(actor),
        action="updates.rollout_completed",
        object_kind="update_rollout",
        object_identifier=str(rollout.id),
        request_id=_request_id(request_id),
        details={
            "status": "completed",
            "target_count": len(targets),
        },
        occurred_at=occurred_at,
    )
    await session.flush()
    return rollout


def _semver_parts(value: str) -> tuple[tuple[int, int, int], list[str] | None]:
    without_build = value.split("+", 1)[0]
    core, separator, prerelease = without_build.partition("-")
    major, minor, patch = (int(part) for part in core.split("."))
    return (major, minor, patch), prerelease.split(".") if separator else None


def _compare_semver(left: str, right: str) -> int:
    left_core, left_pre = _semver_parts(left)
    right_core, right_pre = _semver_parts(right)
    if left_core != right_core:
        return -1 if left_core < right_core else 1
    if left_pre is None or right_pre is None:
        if left_pre is right_pre:
            return 0
        return 1 if left_pre is None else -1
    for left_item, right_item in zip(left_pre, right_pre, strict=False):
        if left_item == right_item:
            continue
        left_numeric = left_item.isdigit()
        right_numeric = right_item.isdigit()
        if left_numeric and right_numeric:
            return -1 if int(left_item) < int(right_item) else 1
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return -1 if left_item < right_item else 1
    if len(left_pre) == len(right_pre):
        return 0
    return -1 if len(left_pre) < len(right_pre) else 1


async def create_rollback_rollout(
    session: AsyncSession,
    triggering_rollout_id: UUID | str,
    build_id: UUID | str,
    device_ids: Sequence[UUID | str],
    reason: str,
    actor: object,
    request_id: str,
    *,
    now: datetime | None = None,
) -> UpdateRollout:
    """Create a new active rollout to an older compatible immutable build."""
    trigger_id = _uuid(triggering_rollout_id, "triggering rollout id")
    rollback_build_id = _uuid(build_id, "rollback build id")
    trigger_build_id = await session.scalar(
        select(UpdateRollout.build_id).where(UpdateRollout.id == trigger_id)
    )
    if trigger_build_id is None:
        raise UpdateNotFound("update rollout not found")
    locked_builds = (
        await session.scalars(
            select(UpdateBuild)
            .where(UpdateBuild.id.in_((trigger_build_id, rollback_build_id)))
            .order_by(UpdateBuild.id)
            .with_for_update()
        )
    ).all()
    builds_by_id = {build.id: build for build in locked_builds}
    trigger_build = builds_by_id.get(trigger_build_id)
    rollback_build = builds_by_id.get(rollback_build_id)
    if trigger_build is None or rollback_build is None:
        raise UpdateNotFound("update build not found")
    trigger = await _locked_rollout(session, trigger_id)
    if trigger.build_id != trigger_build.id:
        raise UpdateConflict("triggering rollout changed during rollback")
    trigger_targets = (
        await session.scalars(
            select(UpdateTarget)
            .where(UpdateTarget.rollout_id == trigger.id)
            .order_by(UpdateTarget.device_id, UpdateTarget.id)
            .with_for_update()
        )
    ).all()
    if not trigger_targets:
        raise UpdateStateError("triggering rollout has no affected devices")
    if trigger.status == "draft":
        raise UpdateStateError("a targetless draft cannot trigger rollback")
    if rollback_build.id == trigger_build.id:
        raise UpdateStateError("rollback build must differ from trigger build")
    if rollback_build.platform != trigger_build.platform:
        raise UpdateStateError("rollback build must target the same platform")
    if _compare_semver(rollback_build.version, trigger_build.version) >= 0:
        raise UpdateStateError("rollback build must be older than trigger build")
    safe_reason = _safe_reason(reason, required=True)
    combined_reason = f"rollback of {trigger.id}; {safe_reason}"
    if len(combined_reason) > 512:
        raise UpdateValidationError("rollback reason is too long")
    normalized_ids, normalized_reason = await _validate_rollout_input(
        rollback_build,
        "rollback",
        device_ids,
        combined_reason,
    )
    targets_by_device = {target.device_id: target for target in trigger_targets}
    if any(device_id not in targets_by_device for device_id in normalized_ids):
        raise UpdateStateError(
            "rollback devices must be a subset of the triggering rollout"
        )
    if any(
        targets_by_device[device_id].status not in _TERMINAL_TARGET_STATUSES
        for device_id in normalized_ids
    ):
        raise UpdateStateError("rollback devices must have terminal trigger targets")
    return await _create_active_rollout(
        session,
        rollback_build,
        "rollback",
        normalized_ids,
        normalized_reason,
        actor_id=_actor_identifier(actor),
        request_id=_request_id(request_id),
        now=_timestamp(now),
    )


async def recommendation_for_device(
    session: AsyncSession,
    device_id: UUID | str,
    platform: str,
    now: datetime | None = None,
) -> AgentUpdateRecommendationV1 | None:
    """Return the one visible active recommendation for a device and platform."""
    _timestamp(now)
    if platform not in _PLATFORMS:
        return None
    row = (
        await session.execute(
            select(UpdateTarget, UpdateRollout, UpdateBuild)
            .join(UpdateRollout, UpdateRollout.id == UpdateTarget.rollout_id)
            .join(UpdateBuild, UpdateBuild.id == UpdateRollout.build_id)
            .where(
                UpdateTarget.device_id == _uuid(device_id, "device id"),
                UpdateTarget.status.in_(_ACTIVE_TARGET_STATUSES),
                UpdateRollout.status == "active",
                UpdateBuild.platform == platform,
            )
            .limit(1)
        )
    ).one_or_none()
    if row is None:
        return None
    target, rollout, build = row
    return AgentUpdateRecommendationV1(
        schema_version="agent_update_recommendation_v1",
        build_identifier=build.build_identifier,
        version=build.version,
        platform=build.platform,
        channel=build.channel,
        artifact_url=build.artifact_url,
        artifact_name=build.artifact_name,
        archive_type=build.archive_type,
        sha256=build.sha256_digest,
        size=build.size,
        operation_id=UUID(target.operation_id),
        reason=target.safe_reason or rollout.reason,
    )


async def _locked_target_context(
    session: AsyncSession,
    device_id: UUID | str,
    operation_id: UUID | str,
) -> tuple[UpdateTarget, UpdateRollout, UpdateBuild]:
    normalized_operation_id = str(_uuid(operation_id, "operation id"))
    normalized_device_id = _uuid(device_id, "device id")
    identity = (
        await session.execute(
            select(
                UpdateTarget.id,
                UpdateTarget.rollout_id,
                UpdateRollout.build_id,
            )
            .join(UpdateRollout, UpdateRollout.id == UpdateTarget.rollout_id)
            .where(
                UpdateTarget.operation_id == normalized_operation_id,
                UpdateTarget.device_id == normalized_device_id,
            )
        )
    ).one_or_none()
    if identity is None:
        raise UpdateNotFound("update operation not found")
    target_id, rollout_id, build_id = identity
    build = await _locked_build(session, build_id)
    rollout = await _locked_rollout(session, rollout_id)
    target = await session.scalar(
        select(UpdateTarget)
        .where(
            UpdateTarget.id == target_id,
            UpdateTarget.rollout_id == rollout.id,
            UpdateTarget.operation_id == normalized_operation_id,
            UpdateTarget.device_id == normalized_device_id,
        )
        .with_for_update()
    )
    if target is None:
        raise UpdateNotFound("update operation not found")
    if rollout.build_id != build.id:
        raise UpdateConflict("update rollout changed during target transition")
    return target, rollout, build


async def record_ack(
    session: AsyncSession,
    *,
    device_id: UUID | str,
    operation_id: UUID | str,
    acknowledgement: AgentUpdateAcknowledgementV1 | Mapping[str, object],
    request_id: str,
    now: datetime | None = None,
    authorization_revalidator: Callable[[], Awaitable[None]] | None = None,
) -> UpdateTarget:
    """Advance one device target through requested and scheduled acknowledgements."""
    validated = _acknowledgement(acknowledgement)
    target, rollout, _ = await _locked_target_context(
        session,
        device_id,
        operation_id,
    )
    if authorization_revalidator is not None:
        await authorization_revalidator()
    if rollout.status != "active":
        raise UpdateStateError("update rollout is not active")
    desired = validated.status
    if desired == "requested":
        if target.status in {"requested", "scheduled"}:
            return target
        if target.status != "assigned":
            raise UpdateStateError("update target cannot acknowledge requested")
    elif desired == "scheduled":
        if target.status == "scheduled":
            return target
        if target.status != "requested":
            raise UpdateStateError("requested acknowledgement must precede scheduled")
    occurred_at = _timestamp(now)
    target.status = desired
    target.updated_at = occurred_at
    if desired == "requested":
        target.requested_at = occurred_at
    else:
        target.scheduled_at = occurred_at
    await append_audit_event(
        session,
        actor_kind="agent",
        actor_identifier=str(target.device_id),
        action="updates.target_acknowledged",
        object_kind="update_target",
        object_identifier=str(target.id),
        request_id=_request_id(request_id),
        details={"status": desired},
        occurred_at=occurred_at,
    )
    await session.flush()
    return target


def _same_report(existing: UpdateReport, report: AgentUpdateReportV1) -> bool:
    return (
        existing.report_key == report.report_key
        and existing.status == report.status
        and existing.reported_version == report.reported_version
        and existing.safe_code == report.safe_code
    )


async def record_report(
    session: AsyncSession,
    *,
    device_id: UUID | str,
    operation_id: UUID | str,
    report: AgentUpdateReportV1 | Mapping[str, object],
    request_id: str,
    now: datetime | None = None,
    authorization_revalidator: Callable[[], Awaitable[None]] | None = None,
) -> UpdateReport:
    """Persist one terminal report idempotently and advance its locked target."""
    validated = _report(report)
    target, rollout, build = await _locked_target_context(
        session,
        device_id,
        operation_id,
    )
    if authorization_revalidator is not None:
        await authorization_revalidator()
    existing = await session.scalar(
        select(UpdateReport)
        .where(
            UpdateReport.update_target_id == target.id,
            UpdateReport.report_key == validated.report_key,
        )
        .with_for_update()
    )
    if existing is not None:
        if _same_report(existing, validated):
            return existing
        raise UpdateConflict("report key already owns a different result")
    if rollout.status not in {"active", "paused"}:
        raise UpdateStateError("update rollout cannot accept terminal reports")
    if target.status not in _ACTIVE_TARGET_STATUSES:
        raise UpdateStateError("update target is already terminal")
    if validated.status in {"applied", "rolled_back"} and target.status != "scheduled":
        raise UpdateStateError("launcher outcome requires scheduled acknowledgement")
    if validated.status == "applied" and validated.reported_version != build.version:
        raise UpdateStateError("applied version does not match assigned build")
    occurred_at = _timestamp(now)
    record = UpdateReport(
        id=uuid4(),
        update_target_id=target.id,
        device_id=target.device_id,
        report_identifier=f"upr_{uuid4().hex}",
        report_key=validated.report_key,
        reported_version=validated.reported_version,
        status=validated.status,
        safe_code=validated.safe_code,
    )
    session.add(record)
    target.status = validated.status
    target.terminal_at = occurred_at
    target.updated_at = occurred_at
    await append_audit_event(
        session,
        actor_kind="agent",
        actor_identifier=str(target.device_id),
        action="updates.target_reported",
        object_kind="update_target",
        object_identifier=str(target.id),
        request_id=_request_id(request_id),
        details={
            "reported_version": validated.reported_version,
            "safe_code": validated.safe_code,
            "status": validated.status,
        },
        occurred_at=occurred_at,
    )
    try:
        await session.flush()
    except IntegrityError as error:
        raise UpdateConflict("report key is already in use") from error
    return record


__all__ = [
    "activate_rollout",
    "complete_rollout",
    "create_rollback_rollout",
    "create_rollout",
    "pause_rollout",
    "recommendation_for_device",
    "record_ack",
    "record_report",
    "register_build",
]
