"""Service-authenticated published module discovery for an exact device."""
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Security

from endpoint_contracts.device_modules import EndpointDeviceModulesPageV1
from endpoint_server.auth.scopes import DEVICES_READ_SCOPE, MODULES_READ_SCOPE, ServicePrincipal, require_service_scope
from endpoint_server.http.correlation import CORRELATION_ID_PATTERN
from endpoint_server.operations.routes import service_bearer, _CORRELATION_RESPONSE_HEADERS, _COMMON_ERROR_RESPONSES
from .device_catalog import CatalogDeviceNotFound, InvalidModuleCursor, project_device_modules

router = APIRouter(prefix="/api/v1", tags=["endpoint-modules"])


@router.get("/devices/{device_id}/modules", response_model=EndpointDeviceModulesPageV1,
    dependencies=[Security(service_bearer, scopes=[DEVICES_READ_SCOPE, MODULES_READ_SCOPE])],
    openapi_extra={"x-required-scopes": [DEVICES_READ_SCOPE, MODULES_READ_SCOPE]},
    responses={200: {"headers": _CORRELATION_RESPONSE_HEADERS},
        400: {"description": "Invalid cursor", "headers": _CORRELATION_RESPONSE_HEADERS},
        404: {"description": "Device not found", "headers": _CORRELATION_RESPONSE_HEADERS}, **_COMMON_ERROR_RESPONSES})
async def read_device_modules(device_id: UUID, request: Request,
    correlation_id: Annotated[str, Header(alias="X-Correlation-ID", min_length=1, max_length=128, pattern=CORRELATION_ID_PATTERN)],
    device_principal: Annotated[ServicePrincipal, Depends(require_service_scope(DEVICES_READ_SCOPE))],
    module_principal: Annotated[ServicePrincipal, Depends(require_service_scope(MODULES_READ_SCOPE))],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    cursor: Annotated[str | None, Query(max_length=1024)] = None) -> EndpointDeviceModulesPageV1:
    connection = await request.app.state.gateway_connection_registry.get(device_id)
    async with request.app.state.session_provider() as session:
        try:
            return await project_device_modules(session, request.app.state.settings, connection, device_id, limit, cursor)
        except CatalogDeviceNotFound:
            raise HTTPException(404, detail={"code": "endpoint_device_not_found"}) from None
        except InvalidModuleCursor:
            raise HTTPException(400, detail={"code": "endpoint_module_cursor_invalid"}) from None
