"""Audited immutable-build and update-rollout domain service."""

from __future__ import annotations

import asyncio
import hashlib
import re
from pathlib import Path
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from pydantic import TypeAdapter, ValidationError
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
from endpoint_contracts.updates import SemanticVersionV1
from endpoint_server.db.instance_order import latest_instance_order
from endpoint_server.audit.service import append_audit_event
from endpoint_server.db.models import (
    Device,
    AuditEvent,
    DeviceInstance,
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
from .admin_contracts import (
    UpdateRolloutCancellationContextV1,
    UpdateRolloutCancellationRequestV1,
    UpdateRolloutCancellationResponseV1,
)
from .admin_transaction import BudgetSession, OperationBudget


_ACTIVE_TARGET_STATUSES = ("assigned", "requested", "scheduled")
_TERMINAL_TARGET_STATUSES = ("applied", "failed", "rolled_back", "cancelled")
_PLATFORMS = ("linux_amd64", "windows_amd64")
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SEMANTIC_VERSION = TypeAdapter(SemanticVersionV1)


def _cancellation_conflict() -> UpdateConflict:
    return UpdateConflict("rollout cancellation context conflicts")


def _operation_identity(operation_id: str) -> str:
    try:
        value = UUID(operation_id)
        if value.int == 0 or operation_id != str(value):
            raise ValueError()
    except (ValueError, AttributeError, TypeError) as error:
        raise _cancellation_conflict() from error
    return hashlib.sha256(("endpoint-update-operation-identity-v1\0" + str(value)).encode("utf-8")).hexdigest()


def _cancellation_context(build: UpdateBuild, rollout: UpdateRollout, target: UpdateTarget,
        *, prior_status: str | None = None) -> UpdateRolloutCancellationContextV1:
    try:
        return UpdateRolloutCancellationContextV1(
            rollout_id=rollout.id, rollout_identifier=rollout.rollout_identifier,
            mode=rollout.mode, status="paused", paused_at=rollout.paused_at,
            build_id=build.id, build_identifier=build.build_identifier,
            artifact_name=build.artifact_name, artifact_sha256=build.sha256_digest,
            target_id=target.id, target_identifier=target.target_identifier,
            device_id=target.device_id, operation_identity=_operation_identity(target.operation_id),
            target_status=prior_status or target.status,
        )
    except ValidationError as error:
        raise _cancellation_conflict() from error


def _require_cancellation_budget(session: AsyncSession, budget: OperationBudget) -> None:
    # The service cannot quietly escape explicit SQL/flush checks via an ordinary session.
    if not isinstance(session, BudgetSession) or session.budget is not budget:
        raise UpdateValidationError("cancellation requires its owned bounded session")
    budget.check()


async def rollout_cancellation_context(session: AsyncSession, rollout_id: UUID,
        *, operation_budget: OperationBudget) -> UpdateRolloutCancellationContextV1:
    """One consistent read of the complete bounded singleton membership."""
    _require_cancellation_budget(session, operation_budget)
    rows = (await session.execute(select(UpdateRollout, UpdateBuild, UpdateTarget)
        .join(UpdateBuild, UpdateBuild.id == UpdateRollout.build_id)
        .outerjoin(UpdateTarget, UpdateTarget.rollout_id == UpdateRollout.id)
        .where(UpdateRollout.id == rollout_id).limit(2))).all()
    if not rows:
        raise UpdateNotFound("rollout not found")
    rollout, build, target = rows[0]
    if (len(rows) != 1 or target is None or rollout.mode != "canary"
            or rollout.status != "paused" or rollout.paused_at is None
            or rollout.completed_at is not None or rollout.cancelled_at is not None
            or target.status not in _ACTIVE_TARGET_STATUSES or target.terminal_at is not None):
        raise _cancellation_conflict()
    return _cancellation_context(build, rollout, target)


async def cancel_paused_singleton_rollout(
    session: AsyncSession, rollout_id: UUID,
    cancellation: UpdateRolloutCancellationRequestV1 | Mapping[str, object], actor: object,
    request_id: str, *, authorization_revalidator: Callable[[], Awaitable[None]],
    operation_budget: OperationBudget, now: datetime | None = None,
) -> UpdateRolloutCancellationResponseV1:
    """Cancel one paused singleton and add its immutable receipt; never commit here."""
    _require_cancellation_budget(session, operation_budget)
    if not callable(authorization_revalidator):
        raise UpdateValidationError("cancellation authority revalidation is required")
    try:
        body = UpdateRolloutCancellationRequestV1.model_validate(
            cancellation.model_dump(mode="json")
            if isinstance(cancellation, UpdateRolloutCancellationRequestV1) else cancellation)
    except ValidationError as error:
        raise UpdateValidationError("invalid cancellation request") from error
    normalized = body.model_dump(mode="json")
    actor_id, correlation_id = _actor_identifier(actor), _request_id(request_id)
    if body.expected.rollout_id != rollout_id:
        raise _cancellation_conflict()
    build_id = await session.scalar(select(UpdateRollout.build_id).where(UpdateRollout.id == rollout_id))
    if build_id is None:
        raise UpdateNotFound("rollout not found")
    build = await session.scalar(select(UpdateBuild).where(UpdateBuild.id == build_id)
        .with_for_update().execution_options(populate_existing=True))
    rollout = await session.scalar(select(UpdateRollout).where(UpdateRollout.id == rollout_id)
        .with_for_update().execution_options(populate_existing=True))
    if build is None or rollout is None or rollout.build_id != build.id:
        raise _cancellation_conflict()
    receipt_id = uuid5(NAMESPACE_URL, "endpoint-platform:update-rollout-cancellation:v1:" + str(rollout.id))
    receipt = await session.scalar(select(AuditEvent).where(AuditEvent.id == receipt_id))
    targets = (await session.scalars(select(UpdateTarget).where(UpdateTarget.rollout_id == rollout.id)
        .limit(2).execution_options(populate_existing=True))).all()
    if len(targets) != 1:
        raise _cancellation_conflict()
    target = targets[0]
    if receipt is not None:
        # Replay only reads retained old membership, avoiding any newer owner's Device lock.
        await authorization_revalidator()
        operation_budget.check()
        try:
            details = receipt.details
            saved = UpdateRolloutCancellationRequestV1.model_validate(details["request"])
            response = UpdateRolloutCancellationResponseV1.model_validate(details["response"])
            if (set(details) != {"version", "request", "response", "prior_rollout_status", "prior_target_status", "target_count"}
                    or details["version"] != 1 or details["target_count"] != 1
                    or details["prior_rollout_status"] != "paused"
                    or details["prior_target_status"] != saved.expected.target_status
                    or saved.model_dump(mode="json") != normalized
                    or details["request"] != saved.model_dump(mode="json")
                    or details["response"] != response.model_dump(mode="json")
                    or receipt.action != "updates.rollout_cancelled" or receipt.actor_kind != "admin"
                    or receipt.actor_identifier != actor_id or receipt.object_kind != "update_rollout"
                    or receipt.object_identifier != str(rollout.id)
                    or rollout.status != "cancelled" or rollout.completed_at is not None
                    or rollout.cancelled_at is None or target.status != "cancelled"
                    or target.terminal_at != rollout.cancelled_at or target.updated_at != rollout.cancelled_at
                    or receipt.created_at != rollout.cancelled_at
                    or not saved.expected.paused_at <= saved.recovery.verified_at <= rollout.cancelled_at
                    or (rollout.cancelled_at - saved.recovery.verified_at).total_seconds() > 1200
                    or _cancellation_context(build, rollout, target,
                        prior_status=saved.expected.target_status) != saved.expected):
                raise _cancellation_conflict()
            expected_response = _cancellation_response(saved, rollout.cancelled_at)
            if response != expected_response:
                raise _cancellation_conflict()
            return response
        except (KeyError, TypeError, ValidationError, AttributeError) as error:
            raise _cancellation_conflict() from error
    if (rollout.mode != "canary" or rollout.status != "paused" or rollout.paused_at is None
            or rollout.completed_at is not None or rollout.cancelled_at is not None):
        raise _cancellation_conflict()
    device = await session.scalar(select(Device).where(Device.id == target.device_id)
        .with_for_update().execution_options(populate_existing=True))
    target = await session.scalar(select(UpdateTarget).where(UpdateTarget.id == target.id)
        .with_for_update().execution_options(populate_existing=True))
    membership = (await session.scalars(select(UpdateTarget.id).where(UpdateTarget.rollout_id == rollout.id)
        .limit(2))).all()
    owners = (await session.scalars(select(UpdateTarget.id).where(
        UpdateTarget.device_id == body.expected.device_id,
        UpdateTarget.status.in_(_ACTIVE_TARGET_STATUSES)).limit(2))).all()
    terminal_report = await session.scalar(select(UpdateReport.id).where(
        UpdateReport.update_target_id == body.expected.target_id,
        UpdateReport.status.in_(("applied", "failed", "rolled_back"))).limit(1))
    if (device is None or device.retired_at is not None or target is None
            or membership != [target.id] or target.rollout_id != rollout.id
            or owners != [target.id] or terminal_report is not None
            or target.status not in _ACTIVE_TARGET_STATUSES or target.terminal_at is not None
            or _cancellation_context(build, rollout, target) != body.expected):
        raise _cancellation_conflict()
    await authorization_revalidator()
    operation_budget.check()
    occurred_at = _timestamp(now)
    verified = body.recovery.verified_at
    if not body.expected.paused_at <= verified <= occurred_at or (occurred_at - verified).total_seconds() > 1200:
        raise _cancellation_conflict()
    response = _cancellation_response(body, occurred_at)
    target.status = "cancelled"
    target.terminal_at = target.updated_at = occurred_at
    rollout.status = "cancelled"
    rollout.cancelled_at = occurred_at
    details = {"version": 1, "request": normalized, "response": response.model_dump(mode="json"),
        "prior_rollout_status": "paused", "prior_target_status": body.expected.target_status, "target_count": 1}
    event = await append_audit_event(session, actor_kind="admin", actor_identifier=actor_id,
        action="updates.rollout_cancelled", object_kind="update_rollout", object_identifier=str(rollout.id),
        request_id=correlation_id, details=details, occurred_at=occurred_at)
    event.id = receipt_id  # new unflushed event only; never rewrite an existing audit
    if event.details != details:
        raise UpdateValidationError("cancellation receipt did not survive audit redaction")
    await session.flush()
    operation_budget.check()
    return response


def _cancellation_response(body: UpdateRolloutCancellationRequestV1,
        occurred_at: datetime) -> UpdateRolloutCancellationResponseV1:
    expected = body.expected
    return UpdateRolloutCancellationResponseV1(
        schema_version="update_rollout_cancellation_response_v1", cancellation_id=body.cancellation_id,
        rollout_id=expected.rollout_id, rollout_identifier=expected.rollout_identifier,
        build_id=expected.build_id, build_identifier=expected.build_identifier,
        target_id=expected.target_id, target_identifier=expected.target_identifier, device_id=expected.device_id,
        operation_identity=expected.operation_identity, artifact_sha256=expected.artifact_sha256,
        reason=body.reason, status="cancelled", target_status="cancelled",
        cancelled_at=occurred_at, terminal_at=occurred_at)


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
        return UpdateBuildManifestV1.model_validate(
            value.model_dump(mode="json")
            if isinstance(value, UpdateBuildManifestV1)
            else value
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
        "minimum_launcher_version": manifest.minimum_launcher_version,
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
    artifact_root: Path | None = None,
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

    if validated.platform == "windows_amd64":
        from endpoint_contracts.runtime_payload import PayloadConflict, safe_path, verify_windows_archive
        try:
            if artifact_root is None or validated.archive_type != "zip":
                raise PayloadConflict()
            name = safe_path(validated.artifact_name)
            if "/" in name:
                raise PayloadConflict()
            await asyncio.to_thread(
                verify_windows_archive, artifact_root.absolute() / name,
                sha256=validated.sha256, size=validated.size, version=validated.version,
                minimum_launcher_version=validated.minimum_launcher_version,
            )
        except (OSError, ValueError) as error:
            raise UpdateValidationError("Windows artifact provenance is invalid") from error

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
    if build.minimum_launcher_version is not None:
        # Read the latest report, including unknown foundation; an older known
        # instance must never authorize an update for the latest installation.
        launcher_version = await session.scalar(
            select(DeviceInstance.launcher_version)
            .where(DeviceInstance.device_id == target.device_id)
            .order_by(*latest_instance_order())
            .limit(1)
        )
        try:
            reported = _SEMANTIC_VERSION.validate_python(launcher_version)
            minimum = _SEMANTIC_VERSION.validate_python(build.minimum_launcher_version)
        except ValidationError:
            return None
        if _compare_semver(reported, minimum) < 0:
            return None
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
    targets = (
        await session.scalars(
            select(UpdateTarget)
            .where(UpdateTarget.rollout_id == rollout.id)
            .order_by(UpdateTarget.id)
            .with_for_update()
        )
    ).all()
    if targets and all(
        item.status in _TERMINAL_TARGET_STATUSES for item in targets
    ):
        rollout.status = "completed"
        rollout.completed_at = occurred_at
        rollout.paused_at = None
        await append_audit_event(
            session,
            actor_kind="system",
            actor_identifier="update-controller",
            action="updates.rollout_completed",
            object_kind="update_rollout",
            object_identifier=str(rollout.id),
            request_id=_request_id(request_id),
            details={"status": "completed", "target_count": len(targets)},
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
