"""Execution-gated HTTP entry point for Endpoint-owned module parents."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from endpoint_contracts.modules import (
    ModuleOperationCreateV1,
    ModuleOperationDetailV1,
    ModuleOperationStepV1,
    ModuleOperationV1,
)
from endpoint_server.auth.scopes import (
    MODULE_OPERATIONS_CREATE_SCOPE,
    MODULE_OPERATIONS_READ_SCOPE,
    ServicePrincipal,
    require_service_scope,
)
from endpoint_server.audit.service import append_audit_event
from endpoint_server.db.models import EndpointOperation, ModuleOperationStep
from endpoint_server.db.models.modules import ModuleDefinition, ModuleVersion
from endpoint_server.http.correlation import CORRELATION_ID_PATTERN
from endpoint_server.policy.network_targets import NetworkTargetPolicyV1

from .operation_service import (
    ModuleOperationConflict,
    ModuleOperationError,
    ModuleOperationNotFound,
    create_module_parent_operation,
)


router = APIRouter(prefix="/api/v1", tags=["endpoint-module-execution"])
_IDEMPOTENCY_KEY_PATTERN = r"^[!-~][ -~]{6,126}[!-~]$"


class ModuleOperationEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    data: ModuleOperationV1


class ModuleOperationDetailEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    data: ModuleOperationDetailV1


def _stored_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _module_operation_error(error: ModuleOperationError) -> HTTPException:
    if isinstance(error, ModuleOperationNotFound):
        status_code = status.HTTP_404_NOT_FOUND
    elif isinstance(error, ModuleOperationConflict):
        status_code = status.HTTP_409_CONFLICT
    else:
        status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    return HTTPException(status_code=status_code, detail={"code": error.code})


async def _project_module_operation(
    session,
    operation: EndpointOperation,
) -> ModuleOperationDetailV1:
    if operation.module_version_id is None or operation.command_id is not None:
        raise ModuleOperationNotFound("module operation was not found")
    version = await session.get(ModuleVersion, operation.module_version_id)
    if version is None:
        raise ModuleOperationNotFound("module operation was not found")
    definition = await session.get(ModuleDefinition, version.module_definition_id)
    if definition is None:
        raise ModuleOperationNotFound("module operation was not found")
    steps = (
        await session.scalars(
            select(ModuleOperationStep)
            .where(ModuleOperationStep.operation_id == operation.id)
            .order_by(ModuleOperationStep.sequence)
        )
    ).all()
    if not steps:
        raise ModuleOperationNotFound("module operation was not found")
    return ModuleOperationDetailV1(
        schema_version="endpoint_module_operation_v1",
        operation_id=operation.id,
        device_id=operation.device_id,
        module_key=definition.module_key,
        version=version.version,
        status=operation.status,
        created_at=_stored_utc(operation.created_at),
        deadline_at=_stored_utc(operation.deadline_at),
        completed_at=_stored_utc(operation.completed_at),
        steps=[
            ModuleOperationStepV1(
                sequence=step.sequence,
                capability=step.capability,
                status=step.status,
                error_code=step.error_code,
                safe_result=step.safe_result_json,
            )
            for step in steps
        ],
    )


@router.post(
    "/devices/{device_id}/module-operations",
    status_code=status.HTTP_201_CREATED,
    response_model=ModuleOperationEnvelope,
)
async def create_module_operation(
    device_id: UUID,
    body: ModuleOperationCreateV1,
    request: Request,
    response: Response,
    principal: Annotated[
        ServicePrincipal,
        Depends(require_service_scope(MODULE_OPERATIONS_CREATE_SCOPE)),
    ],
    idempotency_key: Annotated[
        str,
        Header(
            alias="Idempotency-Key",
            min_length=8,
            max_length=128,
            pattern=_IDEMPOTENCY_KEY_PATTERN,
        ),
    ],
    correlation_id: Annotated[
        str,
        Header(
            alias="X-Correlation-ID",
            min_length=1,
            max_length=128,
            pattern=CORRELATION_ID_PATTERN,
        ),
    ],
) -> ModuleOperationEnvelope:
    """Create/replay a module parent; only Gateway WSS can deliver its children."""
    settings = request.app.state.settings
    policy = NetworkTargetPolicyV1(
        allowed_cidrs=settings.endpoint_network_probe_allowed_cidrs,
        allowed_suffixes=settings.endpoint_network_probe_allowed_suffixes,
    )
    async with request.app.state.session_provider() as session:
        try:
            operation, created = await create_module_parent_operation(
                session,
                service_client_id=principal.client.id,
                device_id=device_id,
                module_key=body.module_key,
                version=body.version,
                inputs=body.inputs,
                idempotency_key=idempotency_key,
                network_policy=policy,
            )
            await session.commit()
        except ModuleOperationError as error:
            await session.rollback()
            raise _module_operation_error(error) from error
        except Exception:
            await session.rollback()
            raise
    if not created:
        response.status_code = status.HTTP_200_OK
    response.headers["X-Correlation-ID"] = correlation_id
    return ModuleOperationEnvelope(
        data=ModuleOperationV1(
            schema_version="endpoint_module_operation_v1",
            operation_id=operation.id,
            device_id=operation.device_id,
            module_key=body.module_key,
            version=body.version,
            status=operation.status,
            created_at=_stored_utc(operation.created_at),
            deadline_at=_stored_utc(operation.deadline_at),
            completed_at=_stored_utc(operation.completed_at),
        )
    )


@router.get(
    "/module-operations/{operation_id}",
    response_model=ModuleOperationDetailEnvelope,
)
async def read_module_operation(
    operation_id: UUID,
    request: Request,
    response: Response,
    principal: Annotated[
        ServicePrincipal,
        Depends(require_service_scope(MODULE_OPERATIONS_READ_SCOPE)),
    ],
    correlation_id: Annotated[
        str,
        Header(
            alias="X-Correlation-ID",
            min_length=1,
            max_length=128,
            pattern=CORRELATION_ID_PATTERN,
        ),
    ],
) -> ModuleOperationDetailEnvelope:
    """Read only a caller-owned parent and its safe typed child summaries."""
    async with request.app.state.session_provider() as session:
        operation = await session.scalar(
            select(EndpointOperation).where(
                EndpointOperation.id == operation_id,
                EndpointOperation.requested_by_service_client_id == principal.client.id,
                EndpointOperation.capability == "endpoint.module.recipe",
            )
        )
        if operation is None:
            raise _module_operation_error(
                ModuleOperationNotFound("module operation was not found")
            )
        try:
            data = await _project_module_operation(session, operation)
            await append_audit_event(
                session,
                actor_kind="service",
                actor_identifier=principal.client.client_identifier,
                action="endpoint.module_operation_read",
                object_kind="endpoint_operation",
                object_identifier=str(operation.id),
                request_id=f"module-operation-{operation.id.hex}",
                details={"status": operation.status},
            )
            await session.commit()
        except ModuleOperationError as error:
            await session.rollback()
            raise _module_operation_error(error) from error
        except Exception:
            await session.rollback()
            raise
    response.headers["X-Correlation-ID"] = correlation_id
    return ModuleOperationDetailEnvelope(data=data)


__all__ = ["router"]
