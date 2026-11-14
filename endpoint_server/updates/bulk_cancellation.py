"""Cancel an entire paused Core rollout whose targets never acknowledged delivery."""

import hashlib
import json
from collections.abc import Awaitable, Callable
from uuid import NAMESPACE_URL, UUID, uuid5

from sqlalchemy import select

from endpoint_server.audit.service import append_audit_event
from endpoint_server.db.models import AuditEvent, UpdateBuild, UpdateReport, UpdateRollout, UpdateTarget

from .admin_contracts import (
    UnrequestedBulkCancellationContext,
    UnrequestedBulkCancellationReceipt,
    UnrequestedBulkCancellationRequest,
)
from .admin_transaction import BudgetSession, OperationBudget
from .errors import UpdateNotFound
from .service import (
    _actor_identifier, _cancellation_conflict, _locked_build, _locked_rollout,
    _operation_identity, _request_id, _require_cancellation_budget, _timestamp,
)


async def _targets(session: BudgetSession, rollout_id: UUID, *, lock: bool) -> list[UpdateTarget]:
    query = (select(UpdateTarget).where(UpdateTarget.rollout_id == rollout_id)
             .order_by(UpdateTarget.id).limit(10_001))
    if lock:
        query = query.with_for_update().execution_options(populate_existing=True)
    return list((await session.scalars(query)).all())


async def _eligible_context(
    session: BudgetSession, rollout: UpdateRollout, build: UpdateBuild, targets: list[UpdateTarget],
) -> UnrequestedBulkCancellationContext:
    if (rollout.mode != "bulk" or rollout.status != "paused" or rollout.paused_at is None
            or rollout.completed_at is not None or rollout.cancelled_at is not None
            or not 1 <= len(targets) <= 10_000):
        raise _cancellation_conflict()
    if any(t.status != "assigned" or t.requested_at is not None or t.scheduled_at is not None
           or t.terminal_at is not None for t in targets):
        raise _cancellation_conflict()
    reported = await session.scalar(select(UpdateReport.id).join(UpdateTarget).where(
        UpdateTarget.rollout_id == rollout.id,
    ).limit(1))
    if reported is not None:
        raise _cancellation_conflict()
    identity = [
        str(build.id), build.sha256_digest,
        [[str(t.id), str(t.device_id), _operation_identity(t.operation_id), t.assigned_at.isoformat()]
         for t in targets],
    ]
    return UnrequestedBulkCancellationContext(
        rollout_id=rollout.id, paused_at=rollout.paused_at, target_count=len(targets),
        membership_sha256=hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest(),
    )


async def bulk_cancellation_context(
    session: BudgetSession, rollout_id: UUID, *, budget: OperationBudget,
) -> UnrequestedBulkCancellationContext:
    _require_cancellation_budget(session, budget)
    # The write path recomputes the preview under locks before changing ownership.
    rollout, build = await _lock_owner(session, rollout_id, readonly=True)
    return await _eligible_context(session, rollout, build, await _targets(session, rollout.id, lock=False))


async def _lock_owner(
    session: BudgetSession, rollout_id: UUID, *, readonly: bool = False,
) -> tuple[UpdateRollout, UpdateBuild]:
    build_id = await session.scalar(select(UpdateRollout.build_id).where(UpdateRollout.id == rollout_id))
    if build_id is None:
        raise UpdateNotFound("rollout not found")
    if readonly:
        build = await session.scalar(select(UpdateBuild).where(UpdateBuild.id == build_id))
        rollout = await session.scalar(select(UpdateRollout).where(UpdateRollout.id == rollout_id))
    else:
        build = await _locked_build(session, build_id)
        rollout = await _locked_rollout(session, rollout_id)
    if build is None or rollout is None or rollout.build_id != build.id:
        raise _cancellation_conflict()
    return rollout, build


async def cancel_unrequested_bulk(
    session: BudgetSession, rollout_id: UUID, body: UnrequestedBulkCancellationRequest,
    actor: object, request_id: str, *, budget: OperationBudget,
    revalidate: Callable[[], Awaitable[None]],
) -> UnrequestedBulkCancellationReceipt:
    _require_cancellation_budget(session, budget)
    if body.expected.rollout_id != rollout_id:
        raise _cancellation_conflict()
    actor_id = _actor_identifier(actor)
    rollout, build = await _lock_owner(session, rollout_id)
    receipt_id = uuid5(NAMESPACE_URL, f"endpoint-platform:unrequested-bulk-cancellation:{rollout_id}")
    event = await session.scalar(select(AuditEvent).where(AuditEvent.id == receipt_id))
    normalized = body.model_dump(mode="json")
    if event is not None:
        if (rollout.status != "cancelled" or event.actor_identifier != actor_id
                or event.actor_kind != "admin" or event.action != "updates.bulk_rollout_cancelled"
                or event.object_kind != "update_rollout" or event.object_identifier != str(rollout_id)
                or event.details.get("request") != normalized):
            raise _cancellation_conflict()
        await revalidate()
        return UnrequestedBulkCancellationReceipt.model_validate(event.details["result"])
    targets = await _targets(session, rollout_id, lock=True)
    if await _eligible_context(session, rollout, build, targets) != body.expected:
        raise _cancellation_conflict()
    await revalidate()
    now = _timestamp(None)
    rollout.status, rollout.cancelled_at = "cancelled", now
    for target in targets:
        target.status = "cancelled"
        target.updated_at = target.terminal_at = now
    receipt = UnrequestedBulkCancellationReceipt(
        cancellation_id=body.cancellation_id, rollout_id=rollout_id,
        target_count=len(targets), cancelled_at=now,
    )
    details = {"request": normalized, "result": receipt.model_dump(mode="json")}
    event = await append_audit_event(
        session, actor_kind="admin", actor_identifier=actor_id, action="updates.bulk_rollout_cancelled",
        object_kind="update_rollout", object_identifier=str(rollout_id),
        request_id=_request_id(request_id), details=details, occurred_at=now,
    )
    event.id = receipt_id
    if event.details != details:
        raise _cancellation_conflict()
    await session.flush()
    return receipt
