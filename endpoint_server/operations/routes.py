"""Feature-gated service routes for the Endpoint Operation v1 boundary."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Request,
    Response,
    Security,
    status,
)
from fastapi.security import HTTPBearer
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_contracts import (
    EndpointDiagnosticResultV1,
    EndpointDeviceCapabilitiesV1,
    EndpointDeviceSummaryV1,
    EndpointOperationCreateV1,
    EndpointOperationV1,
)
from endpoint_server.auth.scopes import (
    DEVICES_READ_SCOPE,
    OPERATIONS_CANCEL_SCOPE,
    OPERATIONS_CREATE_SCOPE,
    OPERATIONS_READ_SCOPE,
    ServicePrincipal,
    require_service_scope,
)
from endpoint_server.context.models import ContextCollection, ContextSnapshot
from endpoint_server.db.models import Device, DeviceInstance, EndpointOperation
from endpoint_server.http.correlation import CORRELATION_ID_PATTERN

from .capabilities import project_available_capabilities
from .projection import project_diagnostic_result, project_operation
from .service import (
    OperationConflict,
    OperationError,
    OperationNotFound,
    OperationValidationError,
    cancel_operation_for_service,
    create_operation_outcome,
    read_operation_for_service,
)


router = APIRouter(prefix="/api/v1", tags=["endpoint-operations"])
service_bearer = HTTPBearer(auto_error=False, scheme_name="ServiceBearer")
IDEMPOTENCY_KEY_PATTERN = r"^[!-~][ -~]{6,126}[!-~]$"
_CORRELATION_RESPONSE_HEADERS = {
    "X-Correlation-ID": {
        "description": "Exact echo of the request tracing header.",
        "schema": {"type": "string", "minLength": 1, "maxLength": 128},
    }
}


class ValidationError(BaseModel):
    """OpenAPI shape of FastAPI's standard request validation item."""

    loc: list[str | int]
    msg: str
    type: str


class HTTPValidationError(BaseModel):
    """OpenAPI shape of FastAPI's standard request validation response."""

    detail: list[ValidationError]


_COMMON_ERROR_RESPONSES = {
    401: {
        "description": "Service authentication failed",
        "headers": _CORRELATION_RESPONSE_HEADERS,
    },
    403: {
        "description": "Service scope is insufficient",
        "headers": _CORRELATION_RESPONSE_HEADERS,
    },
    422: {
        "description": "Validation Error",
        "model": HTTPValidationError,
        "headers": _CORRELATION_RESPONSE_HEADERS,
    },
}


class DeviceCapabilitiesEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    data: EndpointDeviceCapabilitiesV1


class DeviceSummaryEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    data: EndpointDeviceSummaryV1


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


def _echo_correlation(response: Response, correlation_id: str) -> None:
    """Return the caller tracing value without giving it authorization meaning."""
    response.headers["X-Correlation-ID"] = correlation_id


async def _response_data(
    session: AsyncSession,
    operation: EndpointOperation,
) -> OperationResponseData:
    safe_result: EndpointDiagnosticResultV1 | None = None
    if operation.status == "succeeded":
        if operation.context_collection_id is not None:
            snapshot = await session.scalar(
                select(ContextSnapshot)
                .join(
                    ContextCollection,
                    ContextCollection.id == ContextSnapshot.collection_id,
                )
                .where(
                    ContextSnapshot.collection_id == operation.context_collection_id,
                    ContextSnapshot.device_id == operation.device_id,
                    ContextSnapshot.profile == "diagnostic_v1",
                    ContextCollection.operation_id == operation.id,
                    ContextCollection.device_id == operation.device_id,
                    ContextCollection.profile == "diagnostic_v1",
                    ContextCollection.status == "completed",
                )
            )
            if snapshot is not None:
                safe_result = project_diagnostic_result(operation, snapshot)
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
    "/devices/{device_id}",
    response_model=DeviceSummaryEnvelope,
    dependencies=[Security(service_bearer, scopes=[DEVICES_READ_SCOPE])],
    responses={
        200: {"headers": _CORRELATION_RESPONSE_HEADERS},
        404: {
            "description": "Device not found",
            "headers": _CORRELATION_RESPONSE_HEADERS,
        },
        **_COMMON_ERROR_RESPONSES,
    },
    openapi_extra={"x-required-scopes": [DEVICES_READ_SCOPE]},
)
async def read_endpoint_device(
    device_id: UUID,
    request: Request,
    response: Response,
    correlation_id: Annotated[
        str,
        Header(
            alias="X-Correlation-ID",
            min_length=1,
            max_length=128,
            pattern=CORRELATION_ID_PATTERN,
        ),
    ],
    _: Annotated[
        ServicePrincipal,
        Depends(require_service_scope(DEVICES_READ_SCOPE)),
    ],
) -> DeviceSummaryEnvelope:
    """Read one exact safe device summary for verified consumer mapping."""
    async with request.app.state.session_provider() as session:
        device = await session.get(Device, device_id)
        last_seen_at = await session.scalar(
            select(func.max(DeviceInstance.last_seen_at)).where(
                DeviceInstance.device_id == device_id
            )
        )
    if device is None:
        raise _api_error(status.HTTP_404_NOT_FOUND, "endpoint_operation_device_not_found")
    _echo_correlation(response, correlation_id)
    return DeviceSummaryEnvelope(
        data=EndpointDeviceSummaryV1(
            schema_version="endpoint_device_summary_v1",
            device_id=device.id,
            display_name=device.display_name or device.device_identifier,
            retired=device.retired_at is not None,
            last_seen_at=last_seen_at,
        )
    )


@router.get(
    "/devices/{device_id}/capabilities",
    response_model=DeviceCapabilitiesEnvelope,
    dependencies=[Security(service_bearer, scopes=[DEVICES_READ_SCOPE])],
    responses={
        200: {"headers": _CORRELATION_RESPONSE_HEADERS},
        404: {
            "description": "Active device not found",
            "headers": _CORRELATION_RESPONSE_HEADERS,
        },
        **_COMMON_ERROR_RESPONSES,
    },
    openapi_extra={"x-required-scopes": [DEVICES_READ_SCOPE]},
)
async def read_device_operation_capabilities(
    device_id: UUID,
    request: Request,
    response: Response,
    correlation_id: Annotated[
        str,
        Header(
            alias="X-Correlation-ID",
            min_length=1,
            max_length=128,
            pattern=CORRELATION_ID_PATTERN,
        ),
    ],
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
    connection = await request.app.state.gateway_connection_registry.get(
        active_device_id
    )
    _echo_correlation(response, correlation_id)
    return DeviceCapabilitiesEnvelope(
        data=EndpointDeviceCapabilitiesV1(
            schema_version="endpoint_device_capabilities_v1",
            device_id=active_device_id,
            capabilities=project_available_capabilities(
                request.app.state.settings, connection
            ),
        )
    )


@router.post(
    "/devices/{device_id}/operations",
    status_code=status.HTTP_201_CREATED,
    response_model=OperationResponseEnvelope,
    dependencies=[Security(service_bearer, scopes=[OPERATIONS_CREATE_SCOPE])],
    responses={
        200: {
            "model": OperationResponseEnvelope,
            "description": "Replayed endpoint operation",
            "headers": _CORRELATION_RESPONSE_HEADERS,
        },
        201: {"headers": _CORRELATION_RESPONSE_HEADERS},
        409: {
            "description": "Idempotency key conflict",
            "headers": _CORRELATION_RESPONSE_HEADERS,
        },
        503: {
            "description": "Safe result unavailable",
            "headers": _CORRELATION_RESPONSE_HEADERS,
        },
        **_COMMON_ERROR_RESPONSES,
    },
    openapi_extra={"x-required-scopes": [OPERATIONS_CREATE_SCOPE]},
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
        Header(
            alias="Idempotency-Key",
            min_length=8,
            max_length=128,
            pattern=IDEMPOTENCY_KEY_PATTERN,
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
    _echo_correlation(response, correlation_id)
    return OperationResponseEnvelope(data=data)


@router.get(
    "/operations/{operation_id}",
    response_model=OperationResponseEnvelope,
    dependencies=[Security(service_bearer, scopes=[OPERATIONS_READ_SCOPE])],
    responses={
        200: {"headers": _CORRELATION_RESPONSE_HEADERS},
        404: {
            "description": "Endpoint operation not found",
            "headers": _CORRELATION_RESPONSE_HEADERS,
        },
        503: {
            "description": "Safe result unavailable",
            "headers": _CORRELATION_RESPONSE_HEADERS,
        },
        **_COMMON_ERROR_RESPONSES,
    },
    openapi_extra={"x-required-scopes": [OPERATIONS_READ_SCOPE]},
)
async def read_endpoint_operation(
    operation_id: UUID,
    request: Request,
    response: Response,
    correlation_id: Annotated[
        str,
        Header(
            alias="X-Correlation-ID",
            min_length=1,
            max_length=128,
            pattern=CORRELATION_ID_PATTERN,
        ),
    ],
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
    _echo_correlation(response, correlation_id)
    return OperationResponseEnvelope(data=data)


@router.post(
    "/operations/{operation_id}/cancel",
    response_model=OperationResponseEnvelope,
    dependencies=[Security(service_bearer, scopes=[OPERATIONS_CANCEL_SCOPE])],
    responses={
        200: {"headers": _CORRELATION_RESPONSE_HEADERS},
        404: {
            "description": "Endpoint operation not found",
            "headers": _CORRELATION_RESPONSE_HEADERS,
        },
        409: {
            "description": "Operation has already reached delivery or a terminal state",
            "headers": _CORRELATION_RESPONSE_HEADERS,
        },
        **_COMMON_ERROR_RESPONSES,
    },
    openapi_extra={"x-required-scopes": [OPERATIONS_CANCEL_SCOPE]},
)
async def cancel_endpoint_operation(
    operation_id: UUID,
    request: Request,
    response: Response,
    correlation_id: Annotated[
        str,
        Header(
            alias="X-Correlation-ID",
            min_length=1,
            max_length=128,
            pattern=CORRELATION_ID_PATTERN,
        ),
    ],
    principal: Annotated[
        ServicePrincipal,
        Depends(require_service_scope(OPERATIONS_CANCEL_SCOPE)),
    ],
) -> OperationResponseEnvelope:
    """Cancel one owner-scoped operation only while it remains undelivered."""
    async with request.app.state.session_provider() as session:
        try:
            operation = await cancel_operation_for_service(
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
    _echo_correlation(response, correlation_id)
    return OperationResponseEnvelope(data=data)


__all__ = ["router"]
