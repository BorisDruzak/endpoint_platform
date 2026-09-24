"""Session-authenticated, bounded Endpoint Operation journal."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from endpoint_contracts import EndpointDiagnosticResultV1, EndpointOperationV1
from endpoint_contracts.modules import ModuleOperationDetailV1
from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.db.models import Device, EndpointOperation, OperationEvidence, ServiceClient
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.operations.evidence import EvidenceConflict, pin_operation_evidence
from endpoint_server.modules.execution_routes import _project_module_operation
from endpoint_server.modules.operation_service import ModuleOperationNotFound
from endpoint_server.operations.projection import project_operation
from endpoint_server.operations.routes import _response_data
from endpoint_server.operations.service import (
    OperationConflict, OperationError, OperationNotFound, cancel_operation_for_admin,
)


router = APIRouter(prefix="/api/admin/operations", tags=["admin-console-operations"])


class ConsoleOperationSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation_id: UUID
    device_id: UUID
    device_name: str
    capability: str
    status: str
    owner: str
    created_at: datetime
    deadline_at: datetime
    completed_at: datetime | None
    duration_ms: int | None
    error_code: str | None = None


class ConsoleOperationPageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: list[ConsoleOperationSummary]
    total: int
    limit: int
    offset: int


class ConsoleOperationDetailResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: ConsoleOperationSummary
    operation: EndpointOperationV1 | None
    safe_result: EndpointDiagnosticResultV1 | None
    module_detail: ModuleOperationDetailV1 | None
    evidence: "ConsoleEvidenceState | None" = None


class ConsoleEvidenceState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result_available: bool
    result_expires_at: datetime | None
    result_pinned: bool
    result_scrubbed_at: datetime | None
    result_digest: str


class PinEvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=256)


class PinEvidenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: ConsoleEvidenceState


def _evidence_state(evidence: OperationEvidence) -> ConsoleEvidenceState:
    expiry = _aware(evidence.expires_at)
    available = evidence.safe_payload is not None and (
        evidence.pinned_at is not None or (expiry is not None and expiry > datetime.now(UTC))
    )
    return ConsoleEvidenceState(
        result_available=available,
        result_expires_at=expiry,
        result_pinned=evidence.pinned_at is not None,
        result_scrubbed_at=_aware(evidence.scrubbed_at),
        result_digest=evidence.payload_sha256,
    )


class ConsoleOperationActionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: EndpointOperationV1


def _require_operations_enabled(request: Request) -> None:
    if not request.app.state.settings.endpoint_operations_api_enabled:
        raise HTTPException(status_code=404, detail="Операции отключены")


def _aware(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


def _summary(operation: EndpointOperation, device_name: str, owner: str) -> dict[str, object]:
    created = _aware(operation.created_at)
    completed = _aware(operation.completed_at)
    duration_ms = int((completed - created).total_seconds() * 1000) if completed and created else None
    return {
        "operation_id": str(operation.id), "device_id": str(operation.device_id),
        "device_name": device_name, "capability": operation.capability,
        "status": operation.status, "owner": owner,
        "created_at": created, "deadline_at": _aware(operation.deadline_at),
        "completed_at": completed, "duration_ms": duration_ms,
        "error_code": operation.error_code,
    }


@router.post("/{operation_id}/cancel", response_model=ConsoleOperationActionResponse)
async def cancel_admin_operation(
    operation_id: UUID,
    request: Request,
    principal: Annotated[AdminPrincipal, Depends(require_admin)],
) -> ConsoleOperationActionResponse:
    _require_operations_enabled(request)
    async with request.app.state.session_provider() as session:
        try:
            operation = await cancel_operation_for_admin(
                session, operation_id=operation_id, admin_user_id=principal.user.id,
            )
            await session.commit()
        except OperationError as error:
            await session.rollback()
            code = 404 if isinstance(error, OperationNotFound) else 409 if isinstance(error, OperationConflict) else 422
            raise HTTPException(status_code=code, detail="Операцию нельзя отменить") from error
        except Exception:
            await session.rollback()
            raise
    return ConsoleOperationActionResponse(data=project_operation(operation))


@router.get("", response_model=ConsoleOperationPageResponse)
async def list_admin_operations(
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    device_id: UUID | None = None,
    capability: Annotated[str | None, Query(pattern="^(context\\.diagnostic\\.collect|endpoint\\.module\\.recipe)$")] = None,
    operation_status: Literal["queued", "delivered", "acknowledged", "running", "succeeded", "failed", "canceled", "expired"] | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> ConsoleOperationPageResponse:
    _require_operations_enabled(request)
    if since and until and since > until:
        raise HTTPException(status_code=422, detail="Неверный период")
    filters = []
    if device_id: filters.append(EndpointOperation.device_id == device_id)
    if capability: filters.append(EndpointOperation.capability == capability)
    if operation_status: filters.append(EndpointOperation.status == operation_status)
    if since: filters.append(EndpointOperation.created_at >= since)
    if until: filters.append(EndpointOperation.created_at <= until)
    async with request.app.state.session_provider() as session:
        total = await session.scalar(select(func.count()).select_from(EndpointOperation).where(*filters)) or 0
        rows = (await session.execute(
            select(EndpointOperation, Device.display_name, Device.device_identifier, ServiceClient.client_identifier)
            .join(Device, Device.id == EndpointOperation.device_id)
            .join(ServiceClient, ServiceClient.id == EndpointOperation.requested_by_service_client_id)
            .where(*filters)
            .order_by(EndpointOperation.created_at.desc(), EndpointOperation.id.desc())
            .limit(limit).offset(offset)
        )).all()
    return ConsoleOperationPageResponse.model_validate({
        "data": [_summary(operation, name or identifier, owner) for operation, name, identifier, owner in rows],
        "total": total, "limit": limit, "offset": offset,
    })


@router.get("/{operation_id}", response_model=ConsoleOperationDetailResponse)
async def read_admin_operation(
    operation_id: UUID,
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
) -> ConsoleOperationDetailResponse:
    _require_operations_enabled(request)
    async with request.app.state.session_provider() as session:
        row = (await session.execute(
            select(EndpointOperation, Device.display_name, Device.device_identifier, ServiceClient.client_identifier)
            .join(Device, Device.id == EndpointOperation.device_id)
            .join(ServiceClient, ServiceClient.id == EndpointOperation.requested_by_service_client_id)
            .where(EndpointOperation.id == operation_id)
        )).one_or_none()
        if row is None:
            raise HTTPException(status_code=404, detail="Операция не найдена")
        operation, name, identifier, owner = row
        evidence = await session.scalar(select(OperationEvidence).where(OperationEvidence.operation_id == operation_id))
        safe_result = None
        module_detail = None
        projected_operation = None
        if operation.capability == "context.diagnostic.collect" and operation.status == "succeeded":
            data = await _response_data(session, operation)
            safe_result = data.result.model_dump(mode="json") if data.result is not None else None
            projected_operation = data.operation.model_dump(mode="json")
        elif operation.capability == "endpoint.module.recipe":
            try:
                module_detail = (await _project_module_operation(session, operation)).model_dump(mode="json")
            except ModuleOperationNotFound as error:
                raise HTTPException(status_code=503, detail="Детали операции недоступны") from error
        return ConsoleOperationDetailResponse.model_validate({
            "data": _summary(operation, name or identifier, owner),
            "operation": (
                projected_operation or project_operation(operation).model_dump(mode="json")
                if operation.capability == "context.diagnostic.collect" else None
            ),
            "safe_result": safe_result,
            "module_detail": module_detail,
            "evidence": _evidence_state(evidence) if evidence is not None else None,
        })


@router.post("/{operation_id}/evidence/pin", response_model=PinEvidenceResponse)
async def pin_admin_operation_evidence(
    operation_id: UUID,
    body: PinEvidenceRequest,
    request: Request,
    principal: Annotated[AdminPrincipal, Depends(require_admin)],
) -> PinEvidenceResponse:
    _require_operations_enabled(request)
    async with request.app.state.session_provider() as session:
        try:
            evidence = await pin_operation_evidence(
                session, operation_id, actor_kind="admin",
                actor_identifier=str(principal.user.id),
                request_id=audit_request_id(request), reason=body.reason,
            )
            state = _evidence_state(evidence)
            await session.commit()
        except EvidenceConflict as error:
            await session.rollback()
            raise HTTPException(status_code=409, detail="Результат уже недоступен для закрепления") from error
        except Exception:
            await session.rollback()
            raise
    return PinEvidenceResponse(data=state)
