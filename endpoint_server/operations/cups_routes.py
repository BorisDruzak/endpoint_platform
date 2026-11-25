"""Service-scoped operations for a single local CUPS printer."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, Security
from pydantic import AwareDatetime
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from endpoint_contracts.base import ContractModelV1
from endpoint_contracts.commands import CommandStatusV1
from endpoint_contracts.cups_actions import (
    CUPS_ACTION_PARAMETERS, CUPS_QUEUE_CONFIGURE, CUPS_TEST_PAGE_SUBMIT, CupsActionResultV1,
    CupsCapabilityV1, CupsQueueConfigureParametersV1, CupsTestPageParametersV1,
)
from endpoint_server.audit.service import append_audit_event
from endpoint_server.auth.scopes import (
    CUPS_OPERATIONS_READ_SCOPE, CUPS_QUEUE_CONFIGURE_SCOPE, CUPS_TEST_PAGE_SUBMIT_SCOPE,
    ServicePrincipal, require_service_scope,
)
from endpoint_server.db.models import Device, EndpointOperation, ServiceClient
from endpoint_server.http.correlation import CORRELATION_ID_PATTERN
from endpoint_server.operations.routes import service_bearer
from endpoint_server.operations.service import OPERATION_TTL, _advisory_lock, _stored_utc, expire_operation_if_due


router = APIRouter(prefix="/api/v1", tags=["cups-operations"])
IdempotencyKey = Annotated[UUID, Header(alias="Idempotency-Key")]
CorrelationId = Annotated[str, Header(alias="X-Correlation-ID", pattern=CORRELATION_ID_PATTERN)]


class CupsOperationV1(ContractModelV1):
    operation_id: UUID
    device_id: UUID
    capability: CupsCapabilityV1
    status: CommandStatusV1
    created_at: AwareDatetime
    completed_at: AwareDatetime | None
    deadline_at: AwareDatetime
    result: CupsActionResultV1 | None
    error_code: str | None


class CupsOperationEnvelope(ContractModelV1):
    data: CupsOperationV1


def _response(operation: EndpointOperation, response: Response, correlation: str) -> CupsOperationEnvelope:
    response.headers["X-Correlation-ID"] = correlation
    response.headers["Cache-Control"] = "no-store"
    return CupsOperationEnvelope(data=CupsOperationV1(
        operation_id=operation.id, device_id=operation.device_id, capability=operation.capability, status=operation.status,
        created_at=_stored_utc(operation.created_at),
        completed_at=_stored_utc(operation.completed_at) if operation.completed_at is not None else None,
        deadline_at=_stored_utc(operation.deadline_at), result=operation.action_result, error_code=operation.error_code,
    ))


async def _create(
    request: Request, response: Response, principal: ServicePrincipal, device_id: UUID,
    capability: CupsCapabilityV1, parameters: CupsTestPageParametersV1, key: UUID, correlation: str,
) -> CupsOperationEnvelope:
    normalized = parameters.model_dump(mode="json")
    async with request.app.state.session_provider() as session:
        client_id = principal.client.id
        await _advisory_lock(session, f"endpoint.operation:{client_id}:{key}")
        client = await session.scalar(select(ServiceClient).where(
            ServiceClient.id == client_id, ServiceClient.disabled_at.is_(None),
        ).with_for_update())
        if client is None:
            raise HTTPException(403, "CUPS credential is unavailable")
        operation = await session.scalar(select(EndpointOperation).where(
            EndpointOperation.requested_by_service_client_id == client_id,
            EndpointOperation.idempotency_key == str(key),
        ).with_for_update())
        if operation is not None:
            if (operation.device_id, operation.capability, operation.parameters) != (device_id, capability, normalized):
                raise HTTPException(409, "Idempotency-Key already belongs to a different operation")
            await expire_operation_if_due(session, operation)
            response.status_code = 200
        else:
            if await session.scalar(select(Device.id).where(Device.id == device_id, Device.retired_at.is_(None))) is None:
                raise HTTPException(404, "Active device not found")
            now = datetime.now(UTC)
            operation = EndpointOperation(
                id=uuid4(), created_at=now, requested_by_service_client_id=client_id,
                device_id=device_id, idempotency_key=str(key), capability=capability,
                parameters=normalized, status="queued", deadline_at=now + OPERATION_TTL,
            )
            session.add(operation)
            await append_audit_event(
                session, actor_kind="service", actor_identifier=client.client_identifier,
                action="endpoint.cups_action_queued", object_kind="endpoint_operation",
                object_identifier=str(operation.id), request_id=f"cups-operation-{operation.id.hex}",
                details={"device_id": str(device_id), "capability": capability, **normalized},
            )
        try:
            result = _response(operation, response, correlation)
            await session.commit()
        except IntegrityError as error:
            await session.rollback()
            if "uq_endpoint_operations_client_key" not in str(error.orig):
                raise
            raise HTTPException(409, "Idempotency-Key already belongs to a different operation") from error
        return result


@router.post(
    "/devices/{device_id}/cups/queue-configurations", status_code=201, response_model=CupsOperationEnvelope,
    dependencies=[Security(service_bearer, scopes=[CUPS_QUEUE_CONFIGURE_SCOPE])],
    openapi_extra={"x-required-scopes": [CUPS_QUEUE_CONFIGURE_SCOPE]},
)
async def configure_cups_queue(
    device_id: UUID, body: CupsQueueConfigureParametersV1, request: Request, response: Response,
    principal: Annotated[ServicePrincipal, Depends(require_service_scope(CUPS_QUEUE_CONFIGURE_SCOPE))],
    idempotency_key: IdempotencyKey, correlation_id: CorrelationId,
) -> CupsOperationEnvelope:
    """Configure one existing queue in place and preserve spooled jobs."""
    return await _create(request, response, principal, device_id, CUPS_QUEUE_CONFIGURE, body, idempotency_key, correlation_id)


@router.post(
    "/devices/{device_id}/cups/test-pages", status_code=201, response_model=CupsOperationEnvelope,
    dependencies=[Security(service_bearer, scopes=[CUPS_TEST_PAGE_SUBMIT_SCOPE])],
    openapi_extra={"x-required-scopes": [CUPS_TEST_PAGE_SUBMIT_SCOPE]},
)
async def submit_cups_test_page(
    device_id: UUID, body: CupsTestPageParametersV1, request: Request, response: Response,
    principal: Annotated[ServicePrincipal, Depends(require_service_scope(CUPS_TEST_PAGE_SUBMIT_SCOPE))],
    idempotency_key: IdempotencyKey, correlation_id: CorrelationId,
) -> CupsOperationEnvelope:
    """Submit one fixed page to an existing local queue using a stable key."""
    return await _create(request, response, principal, device_id, CUPS_TEST_PAGE_SUBMIT, body, idempotency_key, correlation_id)


@router.get(
    "/cups-operations/{operation_id}", response_model=CupsOperationEnvelope,
    dependencies=[Security(service_bearer, scopes=[CUPS_OPERATIONS_READ_SCOPE])],
    openapi_extra={"x-required-scopes": [CUPS_OPERATIONS_READ_SCOPE]},
)
async def read_cups_operation(
    operation_id: UUID, request: Request, response: Response, correlation_id: CorrelationId,
    principal: Annotated[ServicePrincipal, Depends(require_service_scope(CUPS_OPERATIONS_READ_SCOPE))],
) -> CupsOperationEnvelope:
    async with request.app.state.session_provider() as session:
        operation = await session.scalar(select(EndpointOperation).where(
            EndpointOperation.id == operation_id, EndpointOperation.requested_by_service_client_id == principal.client.id,
            EndpointOperation.capability.in_(tuple(CUPS_ACTION_PARAMETERS)),
        ).with_for_update())
        if operation is None:
            raise HTTPException(404, "CUPS operation not found")
        await expire_operation_if_due(session, operation)
        result = _response(operation, response, correlation_id)
        await session.commit()
        return result
