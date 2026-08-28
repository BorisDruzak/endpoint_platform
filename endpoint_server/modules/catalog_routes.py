"""Read-only API for Endpoint's closed module capability catalog."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Security
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


router = APIRouter(prefix="/api/v1", tags=["endpoint-modules"])
service_bearer = HTTPBearer(auto_error=False, scheme_name="ServiceBearer")


class ModuleCapabilityCatalogEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    data: ModuleCapabilityCatalogV1


@router.get(
    "/module-capabilities",
    response_model=ModuleCapabilityCatalogEnvelope,
    dependencies=[Security(service_bearer, scopes=[MODULES_READ_SCOPE])],
    openapi_extra={"x-required-scopes": [MODULES_READ_SCOPE]},
)
async def get_module_capabilities(
    _: ServicePrincipal = Depends(require_service_scope(MODULES_READ_SCOPE)),
) -> ModuleCapabilityCatalogEnvelope:
    """Expose only versioned metadata from the server-owned closed registry."""
    return ModuleCapabilityCatalogEnvelope(data=module_capability_catalog())
