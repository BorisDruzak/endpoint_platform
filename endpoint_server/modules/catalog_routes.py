"""Read-only API for Endpoint's closed module capability catalog."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, Security
from fastapi.security import HTTPBearer
from pydantic import BaseModel, ConfigDict

from endpoint_contracts.capabilities import (
    ModuleCapabilityCatalogV1,
    module_capability_catalog,
)
from endpoint_server.auth.scopes import (
    MODULES_READ_SCOPE,
    ServicePrincipal,
    require_service_scope,
)
from endpoint_server.http.correlation import CORRELATION_ID_PATTERN


router = APIRouter(prefix="/api/v1", tags=["endpoint-modules"])
service_bearer = HTTPBearer(auto_error=False, scheme_name="ServiceBearer")
_CORRELATION_RESPONSE_HEADERS = {
    "X-Correlation-ID": {
        "description": "Exact echo of the request tracing header.",
        "schema": {"type": "string", "minLength": 1, "maxLength": 128},
    }
}


class ModuleCapabilityCatalogEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    data: ModuleCapabilityCatalogV1


@router.get(
    "/module-capabilities",
    response_model=ModuleCapabilityCatalogEnvelope,
    dependencies=[Security(service_bearer, scopes=[MODULES_READ_SCOPE])],
    responses={
        200: {"headers": _CORRELATION_RESPONSE_HEADERS},
        401: {
            "description": "Service authentication failed",
            "headers": _CORRELATION_RESPONSE_HEADERS,
        },
        403: {
            "description": "Service scope is insufficient",
            "headers": _CORRELATION_RESPONSE_HEADERS,
        },
    },
    openapi_extra={"x-required-scopes": [MODULES_READ_SCOPE]},
)
async def get_module_capabilities(
    correlation_id: Annotated[
        str,
        Header(
            alias="X-Correlation-ID",
            min_length=1,
            max_length=128,
            pattern=CORRELATION_ID_PATTERN,
        ),
    ],
    _: ServicePrincipal = Depends(require_service_scope(MODULES_READ_SCOPE)),
) -> ModuleCapabilityCatalogEnvelope:
    """Expose only versioned metadata from the server-owned closed registry."""
    return ModuleCapabilityCatalogEnvelope(data=module_capability_catalog())
