"""Transactional safe-result retention and audited evidence pinning."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_server.audit.service import append_audit_event
from endpoint_server.db.models.operations import EndpointOperation, ModuleOperationStep, OperationEvidence
from endpoint_server.context.policy import OPERATION_RESULT_TTL
from endpoint_server.operations.redaction import sanitize_agent_public_text


class EvidenceConflict(ValueError):
    pass


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("evidence timestamp must be timezone-aware")
    return value.astimezone(UTC)


async def create_operation_evidence(
    session: AsyncSession,
    operation: EndpointOperation,
    *,
    result_kind: str,
    safe_payload: dict[str, object],
    created_at: datetime,
) -> OperationEvidence:
    """Only call with an existing validated server safe projection."""
    if result_kind not in {"diagnostic", "module"}:
        raise ValueError("unsupported result kind")
    rendered = json.dumps(safe_payload, sort_keys=True, ensure_ascii=True, allow_nan=False)
    if len(rendered.encode()) > 65_536:
        raise ValueError("safe operation result exceeds evidence bound")
    encoded = json.dumps(safe_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    when = _utc(created_at)
    existing = await session.scalar(select(OperationEvidence).where(OperationEvidence.operation_id == operation.id).with_for_update())
    if existing is not None:
        raise EvidenceConflict("operation evidence already exists")
    evidence = OperationEvidence(
        id=uuid4(), operation_id=operation.id, result_kind=result_kind,
        safe_payload=safe_payload, payload_sha256=hashlib.sha256(encoded).hexdigest(),
        created_at=when, expires_at=when + OPERATION_RESULT_TTL,
    )
    session.add(evidence)
    await session.flush()
    return evidence


async def pin_operation_evidence(
    session: AsyncSession,
    operation_id: UUID,
    *,
    actor_kind: str,
    actor_identifier: str,
    request_id: str,
    reason: str | None = None,
    now: datetime | None = None,
) -> OperationEvidence:
    if reason is not None and len(reason) > 256:
        raise ValueError("pin reason is too long")
    safe_reason = sanitize_agent_public_text(reason, limit=256)[0] if reason is not None else None
    when = _utc(now or datetime.now(UTC))
    evidence = await session.scalar(select(OperationEvidence).where(OperationEvidence.operation_id == operation_id).with_for_update())
    if evidence is None or evidence.safe_payload is None or evidence.scrubbed_at is not None:
        raise EvidenceConflict("operation result is unavailable")
    if evidence.pinned_at is not None:
        return evidence
    expiry = evidence.expires_at
    if expiry is None or (expiry.replace(tzinfo=UTC) if expiry.tzinfo is None else expiry.astimezone(UTC)) <= when:
        raise EvidenceConflict("operation result has expired")
    operation = await session.get(EndpointOperation, operation_id)
    if operation is None:
        raise EvidenceConflict("operation is unavailable")
    evidence.pinned_at = when
    evidence.expires_at = None
    evidence.pinned_by_actor_kind = actor_kind
    evidence.pinned_by_actor_identifier = actor_identifier[:128]
    evidence.pin_reason = safe_reason
    await append_audit_event(
        session, actor_kind=actor_kind, actor_identifier=actor_identifier,
        action="operation_evidence.pinned", object_kind="endpoint_operation",
        object_identifier=str(operation_id), request_id=request_id,
        details={"operation_id": str(operation_id), "device_id": str(operation.device_id), "reason": safe_reason},
        occurred_at=when,
    )
    await session.flush()
    return evidence


async def cleanup_operation_results(session: AsyncSession, *, now: datetime | None = None, limit: int = 100) -> int:
    if not 1 <= limit <= 1000:
        raise ValueError("cleanup limit must be between 1 and 1000")
    when = _utc(now or datetime.now(UTC))
    rows = (await session.scalars(
        select(OperationEvidence)
        .where(OperationEvidence.expires_at <= when, OperationEvidence.safe_payload.is_not(None), OperationEvidence.pinned_at.is_(None))
        .order_by(OperationEvidence.expires_at, OperationEvidence.id)
        .limit(limit).with_for_update(skip_locked=True)
    )).all()
    for evidence in rows:
        evidence.safe_payload = None
        evidence.scrubbed_at = when
        steps = (await session.scalars(select(ModuleOperationStep).where(ModuleOperationStep.operation_id == evidence.operation_id, ModuleOperationStep.safe_result_json.is_not(None)).with_for_update())).all()
        for step in steps:
            step.safe_result_json = None
    await session.flush()
    return len(rows)


async def cleanup_module_step_results(session: AsyncSession, *, now: datetime | None = None, limit: int = 100) -> int:
    """Scrub old step copies, including operations that predate evidence rows."""
    if not 1 <= limit <= 1000:
        raise ValueError("cleanup limit must be between 1 and 1000")
    cutoff = _utc(now or datetime.now(UTC)) - OPERATION_RESULT_TTL
    rows = (await session.scalars(select(ModuleOperationStep).where(
        ModuleOperationStep.completed_at < cutoff,
        ModuleOperationStep.safe_result_json.is_not(None),
    ).order_by(ModuleOperationStep.completed_at, ModuleOperationStep.id)
        .limit(limit).with_for_update(skip_locked=True))).all()
    for step in rows:
        step.safe_result_json = None
    await session.flush()
    return len(rows)
