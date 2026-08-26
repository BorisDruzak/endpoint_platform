from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from endpoint_contracts.modules import ModuleVersionCreateV1
from endpoint_server.auth.scopes import (
    MODULES_WRITE_SCOPE,
    ServicePrincipal,
    require_service_scope,
)

from .service import ModuleServiceError, persist_draft_version


router = APIRouter(prefix="/api/v1/modules", tags=["endpoint-modules"])


@router.post("/versions", status_code=status.HTTP_201_CREATED)
async def create_module_version(
    body: ModuleVersionCreateV1,
    request: Request,
    _: ServicePrincipal = Depends(require_service_scope(MODULES_WRITE_SCOPE)),
) -> dict[str, object]:
    async with request.app.state.session_provider() as session:
        try:
            version = await persist_draft_version(
                session,
                recipe=body.recipe,
                display_name=body.display_name,
                version=body.version,
            )
            await session.commit()
        except ModuleServiceError as error:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "endpoint_module_version_conflict"},
            ) from error
    return {"data": {"module_version_id": str(version.id), "state": version.state}}
