from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from endpoint_contracts.modules import (
    ModuleValidationRunV1,
    ModuleVersionCreateV1,
    ModuleVersionStateV1,
)
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.audit.service import append_audit_event
from endpoint_server.auth.scopes import (
    MODULES_PUBLISH_SCOPE,
    MODULES_VALIDATE_SCOPE,
    MODULES_WRITE_SCOPE,
    ServicePrincipal,
    require_service_scope,
)
from endpoint_server.db.models import ModuleDefinition, ModuleVersion

from .service import (
    ModuleServiceError,
    persist_draft_version,
    publish_persisted_module_version,
    transition_persisted_version,
    validate_persisted_module_version,
)


router = APIRouter(prefix="/api/v1/modules", tags=["endpoint-modules"])


class ModuleValidationEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    data: ModuleValidationRunV1


class ModuleVersionStateEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    data: ModuleVersionStateV1


@router.post("/versions", status_code=status.HTTP_201_CREATED)
async def create_module_version(
    body: ModuleVersionCreateV1,
    request: Request,
    principal: ServicePrincipal = Depends(require_service_scope(MODULES_WRITE_SCOPE)),
) -> dict[str, object]:
    async with request.app.state.session_provider() as session:
        try:
            version = await persist_draft_version(
                session,
                recipe=body.recipe,
                display_name=body.display_name,
                version=body.version,
            )
        except ModuleServiceError as error:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "endpoint_module_version_conflict"},
            ) from error
        try:
            await append_audit_event(
                session,
                actor_kind="service",
                actor_identifier=principal.client.client_identifier,
                action="endpoint.module_version_created",
                object_kind="module_version",
                object_identifier=str(version.id),
                request_id=audit_request_id(request),
                details={
                    "module_key": body.recipe.module_key,
                    "version": body.version,
                    "state": version.state,
                },
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return {"data": {"module_version_id": str(version.id), "state": version.state}}


@router.post(
    "/{module_key}/versions/{version}/validate",
    response_model=ModuleValidationEnvelope,
)
async def validate_module_version(
    module_key: str,
    version: str,
    request: Request,
    principal: ServicePrincipal = Depends(require_service_scope(MODULES_VALIDATE_SCOPE)),
) -> ModuleValidationEnvelope:
    async with request.app.state.session_provider() as session:
        module_version = await session.scalar(
            select(ModuleVersion)
            .join(ModuleDefinition)
            .where(
                ModuleDefinition.module_key == module_key,
                ModuleVersion.version == version,
            )
        )
        if module_version is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "endpoint_module_version_not_found"},
            )
        try:
            validation_run = await validate_persisted_module_version(
                session,
                module_version,
            )
        except ModuleServiceError as error:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "endpoint_module_validation_conflict"},
            ) from error
        try:
            await append_audit_event(
                session,
                actor_kind="service",
                actor_identifier=principal.client.client_identifier,
                action="endpoint.module_validation_completed",
                object_kind="module_version",
                object_identifier=str(module_version.id),
                request_id=audit_request_id(request),
                details={
                    "module_key": module_key,
                    "version": version,
                    "status": validation_run.status,
                    "error_codes": validation_run.error_codes,
                },
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return ModuleValidationEnvelope(
        data=ModuleValidationRunV1(
            schema_version="module_validation_run_v1",
            module_key=module_key,
            version=version,
            status=validation_run.status,
            error_codes=validation_run.error_codes,
            warning_codes=validation_run.warning_codes,
            completed_at=validation_run.completed_at,
        )
    )


@router.post(
    "/{module_key}/versions/{version}/publish",
    response_model=ModuleVersionStateEnvelope,
)
async def publish_module_version(
    module_key: str,
    version: str,
    request: Request,
    principal: ServicePrincipal = Depends(require_service_scope(MODULES_PUBLISH_SCOPE)),
) -> ModuleVersionStateEnvelope:
    async with request.app.state.session_provider() as session:
        module_version = await session.scalar(
            select(ModuleVersion)
            .join(ModuleDefinition)
            .where(
                ModuleDefinition.module_key == module_key,
                ModuleVersion.version == version,
            )
        )
        if module_version is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "endpoint_module_version_not_found"},
            )
        try:
            published = await publish_persisted_module_version(session, module_version)
        except ModuleServiceError as error:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "endpoint_module_publication_conflict"},
            ) from error
        try:
            await append_audit_event(
                session,
                actor_kind="service",
                actor_identifier=principal.client.client_identifier,
                action="endpoint.module_published",
                object_kind="module_version",
                object_identifier=str(published.id),
                request_id=audit_request_id(request),
                details={
                    "module_key": module_key,
                    "version": version,
                    "state": published.state,
                },
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return ModuleVersionStateEnvelope(
        data=ModuleVersionStateV1(
            schema_version="module_version_state_v1",
            module_key=module_key,
            version=version,
            state=published.state,
        )
    )


@router.post(
    "/{module_key}/versions/{version}/deprecate",
    response_model=ModuleVersionStateEnvelope,
)
async def deprecate_module_version(
    module_key: str,
    version: str,
    request: Request,
    principal: ServicePrincipal = Depends(require_service_scope(MODULES_PUBLISH_SCOPE)),
) -> ModuleVersionStateEnvelope:
    """Stop new module operations from using one immutable published version."""
    async with request.app.state.session_provider() as session:
        module_version = await session.scalar(
            select(ModuleVersion)
            .join(ModuleDefinition)
            .where(
                ModuleDefinition.module_key == module_key,
                ModuleVersion.version == version,
            )
        )
        if module_version is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "endpoint_module_version_not_found"},
            )
        try:
            deprecated = await transition_persisted_version(
                session, module_version, "deprecated"
            )
        except ModuleServiceError as error:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "endpoint_module_deprecation_conflict"},
            ) from error
        try:
            await append_audit_event(
                session,
                actor_kind="service",
                actor_identifier=principal.client.client_identifier,
                action="endpoint.module_deprecated",
                object_kind="module_version",
                object_identifier=str(deprecated.id),
                request_id=audit_request_id(request),
                details={
                    "module_key": module_key,
                    "version": version,
                    "state": deprecated.state,
                },
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    return ModuleVersionStateEnvelope(
        data=ModuleVersionStateV1(
            schema_version="module_version_state_v1",
            module_key=module_key,
            version=version,
            state=deprecated.state,
        )
    )
