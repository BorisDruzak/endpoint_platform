"""Execution-gated HTTP entry point for Endpoint-owned module parents."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict

from endpoint_contracts.modules import ModuleOperationCreateV1, ModuleOperationV1
from endpoint_server.auth.scopes import (
    MODULE_OPERATIONS_CREATE_SCOPE,
    ServicePrincipal,
    require_service_scope,
)
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


__all__ = ["router"]
