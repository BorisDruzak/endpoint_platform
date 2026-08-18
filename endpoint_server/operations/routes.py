"""Feature-gated service routes for the Endpoint Operation v1 boundary."""

from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Request,
    Response,
    status,
)
from pydantic import BaseModel, ConfigDict, Field, StrictBool
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_contracts import (
    EndpointDiagnosticResultV1,
    EndpointOperationCreateV1,
    EndpointOperationV1,
)
from endpoint_server.auth.scopes import (
    DEVICES_READ_SCOPE,
    OPERATIONS_CREATE_SCOPE,
    OPERATIONS_READ_SCOPE,
    ServicePrincipal,
    require_service_scope,
)
from endpoint_server.context.models import ContextSnapshot
from endpoint_server.db.models import Device, EndpointOperation

from .capabilities import SUPPORTED_CAPABILITIES
from .projection import project_diagnostic_result, project_operation
from .service import (
    OperationConflict,
    OperationError,
    OperationNotFound,
    OperationValidationError,
    create_operation_outcome,
    read_operation_for_service,
)


router = APIRouter(prefix="/api/v1", tags=["endpoint-operations"])


class CapabilityAvailability(BaseModel):
    """One server-supported capability without endpoint or session internals."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capability: Literal["context.diagnostic.collect"]
    available: StrictBool


class DeviceCapabilities(BaseModel):
    """Safe operation availability for one active route device."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    device_id: UUID
    capabilities: list[CapabilityAvailability] = Field(max_length=1)


class DeviceCapabilitiesEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    data: DeviceCapabilities


class OperationResponseData(BaseModel):
    """Public operation lifecycle and its optional validated safe result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operation: EndpointOperationV1
    result: EndpointDiagnosticResultV1 | None


class OperationResponseEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    data: OperationResponseData


def _api_error(status_code: int, code: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"code": code})


def _operation_error(error: OperationError) -> HTTPException:
    if isinstance(error, OperationConflict):
        return _api_error(status.HTTP_409_CONFLICT, error.code)
    if isinstance(error, OperationValidationError):
        return _api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, error.code)
    if isinstance(error, OperationNotFound):
        return _api_error(status.HTTP_404_NOT_FOUND, error.code)
    return _api_error(status.HTTP_400_BAD_REQUEST, error.code)


async def _response_data(
    session: AsyncSession,
    operation: EndpointOperation,
) -> OperationResponseData:
    safe_result: EndpointDiagnosticResultV1 | None = None
    if operation.status == "succeeded":
        if operation.context_collection_id is not None:
            snapshot = await session.scalar(
                select(ContextSnapshot).where(
                    ContextSnapshot.collection_id == operation.context_collection_id
                )
            )
            if snapshot is not None:
                safe_result = project_diagnostic_result(snapshot)
        if safe_result is None:
            raise _api_error(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "endpoint_operation_result_unavailable",
            )
    return OperationResponseData(
        operation=project_operation(operation),
        result=safe_result,
    )


@router.get(
    "/devices/{device_id}/capabilities",
    response_model=DeviceCapabilitiesEnvelope,
)
async def read_device_operation_capabilities(
    device_id: UUID,
    request: Request,
    _: Annotated[
        ServicePrincipal,
        Depends(require_service_scope(DEVICES_READ_SCOPE)),
    ],
) -> DeviceCapabilitiesEnvelope:
    """Report only server acceptance for an active device and fixed capability."""
    async with request.app.state.session_provider() as session:
        active_device_id = await session.scalar(
            select(Device.id).where(
                Device.id == device_id,
                Device.retired_at.is_(None),
            )
        )
    if active_device_id is None:
        raise _api_error(
            status.HTTP_404_NOT_FOUND,
            "endpoint_operation_device_not_found",
        )
    return DeviceCapabilitiesEnvelope(
        data=DeviceCapabilities(
            device_id=active_device_id,
            capabilities=[
                CapabilityAvailability(capability=capability, available=True)
                for capability in sorted(SUPPORTED_CAPABILITIES)
            ],
        )
    )


@router.post(
    "/devices/{device_id}/operations",
    status_code=status.HTTP_201_CREATED,
    response_model=OperationResponseEnvelope,
)
async def create_device_operation(
    device_id: UUID,
    body: EndpointOperationCreateV1,
    request: Request,
    response: Response,
    principal: Annotated[
        ServicePrincipal,
        Depends(require_service_scope(OPERATIONS_CREATE_SCOPE)),
    ],
    idempotency_key: Annotated[
        str,
        Header(alias="Idempotency-Key", min_length=8, max_length=128),
    ],
) -> OperationResponseEnvelope:
    """Create or replay one operation owned by the authenticated service client."""
    async with request.app.state.session_provider() as session:
        try:
            operation, created = await create_operation_outcome(
                session,
                request=body,
                service_client_id=principal.client.id,
                device_id=device_id,
                idempotency_key=idempotency_key,
            )
            data = await _response_data(session, operation)
            await session.commit()
        except OperationError as error:
            await session.rollback()
            raise _operation_error(error) from error
        except Exception:
            await session.rollback()
            raise
    if not created:
        response.status_code = status.HTTP_200_OK
    return OperationResponseEnvelope(data=data)


@router.get(
    "/operations/{operation_id}",
    response_model=OperationResponseEnvelope,
)
async def read_endpoint_operation(
    operation_id: UUID,
    request: Request,
    principal: Annotated[
        ServicePrincipal,
        Depends(require_service_scope(OPERATIONS_READ_SCOPE)),
    ],
) -> OperationResponseEnvelope:
    """Read one operation through stable service-client ownership."""
    async with request.app.state.session_provider() as session:
        try:
            operation = await read_operation_for_service(
                session,
                operation_id=operation_id,
                service_client_id=principal.client.id,
            )
            data = await _response_data(session, operation)
            await session.commit()
        except OperationError as error:
            await session.rollback()
            raise _operation_error(error) from error
        except Exception:
            await session.rollback()
            raise
    return OperationResponseEnvelope(data=data)


__all__ = ["router"]
