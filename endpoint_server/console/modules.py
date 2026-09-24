"""Browser-safe Module Workbench over the canonical Endpoint domain services."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Query, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import func, select

from endpoint_contracts.capabilities import ModuleCapabilityAuthoringV1, module_capability_catalog
from endpoint_contracts.modules import (
    EndpointRecipeModuleSpecV1, ModuleInputNameV1, ModuleLabOperationCreateV1,
    ModuleOperationCreateV1, ModuleOperationInputValueV1, ModuleRecipeInputV1,
    ModuleVersionCreateV1, ModuleVersionViewV1,
)
from endpoint_server.audit.request_ids import audit_request_id
from endpoint_server.audit.service import append_audit_event
from endpoint_server.auth.admin_sessions import AdminPrincipal, require_admin
from endpoint_server.db.models import (
    Device, ModuleDefinition, ModuleLiveTest, ModuleValidationRun,
    ModuleVersion, ServiceClient,
)
from endpoint_server.modules.operation_service import ModuleOperationError, create_module_parent_operation
from endpoint_server.modules.lifecycle import ModuleLifecycleError
from endpoint_server.modules.service import (
    ModuleServiceError, accept_persisted_module_labs, persist_draft_version,
    publish_persisted_module_version, record_module_live_test,
    transition_persisted_version, validate_persisted_module_version,
)
from endpoint_server.operations.capabilities import compatible_module_capabilities
from endpoint_server.policy.network_targets import NetworkTargetPolicyV1


router = APIRouter(prefix="/api/admin/console", tags=["admin-console-modules"])
_OWNER_IDENTIFIER = "endpoint-console-internal"
_CAPABILITY_DISPLAY_NAMES = {
    "dns.resolve": "Разрешение DNS-имени",
    "network.ping": "Проверка доступности сети",
    "tcp.connect": "Проверка TCP-соединения",
    "route.get": "Просмотр маршрута",
    "adapter.list": "Список сетевых адаптеров",
    "system.service_status": "Состояние службы",
}
ModuleKey = Annotated[str, Path(min_length=1, max_length=128)]


class ConsoleModuleLabOperationCreateV1(ModuleLabOperationCreateV1):
    inputs: dict[ModuleInputNameV1, ModuleOperationInputValueV1] = Field(
        min_length=0, max_length=8,
    )


class ConsoleModuleOperationCreateV1(ModuleOperationCreateV1):
    inputs: dict[ModuleInputNameV1, ModuleOperationInputValueV1] = Field(
        min_length=0, max_length=8,
    )


class ConsoleModuleValidation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["succeeded", "failed"]
    validator_version: str
    error_codes: list[str]
    warning_codes: list[str]
    completed_at: datetime


class ConsoleModuleLab(BaseModel):
    model_config = ConfigDict(extra="forbid")

    platform: Literal["linux_amd64", "windows_amd64"]
    status: Literal["passed", "failed"]
    operation_id: UUID
    device_id: UUID
    tested_at: datetime


class ConsoleModuleVersionDetail(ModuleVersionViewV1):
    id: UUID
    created_at: datetime
    validations_total: int
    validation_limit: int
    validation_offset: int
    labs_total: int
    lab_limit: int
    lab_offset: int
    passed_lab_platforms: list[Literal["linux_amd64", "windows_amd64"]]
    validations: list[ConsoleModuleValidation]
    labs: list[ConsoleModuleLab]


class ConsoleModuleVersionDetailResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: ConsoleModuleVersionDetail


class ConsoleCapabilityItem(ModuleCapabilityAuthoringV1):
    display_name: str


class ConsoleCapabilityCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["endpoint_module_capability_catalog_v1"]
    items: list[ConsoleCapabilityItem]


class ConsoleCapabilityCatalogResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: ConsoleCapabilityCatalog


class ConsoleModuleVersionSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    version: str
    state: str
    created_at: datetime


class ConsoleModuleSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    module_key: str
    display_name: str
    versions: list[ConsoleModuleVersionSummary]


class ConsoleModulePageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: list[ConsoleModuleSummary]
    total: int
    limit: int
    offset: int


class ConsoleModuleCreated(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    module_key: str
    version: str
    state: str


class ConsoleModuleCreateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: ConsoleModuleCreated


class ConsoleModuleValidationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: ConsoleModuleValidation


class ConsoleModuleTransition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    module_key: str
    version: str
    state: str


class ConsoleModuleTransitionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: ConsoleModuleTransition


class ConsoleModuleLabResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    platform: Literal["linux_amd64", "windows_amd64"]
    status: Literal["passed", "failed"]
    tested_at: datetime


class ConsoleModuleLabResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: ConsoleModuleLabResult


class ConsoleLabDevice(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    display_name: str


class ConsoleLabDevicePageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: list[ConsoleLabDevice]
    total: int
    limit: int
    offset: int


class ConsoleModuleOperationCreated(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation_id: UUID
    status: str
    created: bool


class ConsoleModuleOperationCreateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: ConsoleModuleOperationCreated


class ConsoleDeviceModule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    module_key: str
    display_name: str
    version: str
    compatible: bool
    reason: str | None
    inputs: list[ModuleRecipeInputV1]


class ConsoleDeviceModulePageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: list[ConsoleDeviceModule]
    total: int
    limit: int
    offset: int


ModuleVersionName = Annotated[str, Path(pattern=r"^\d+\.\d+\.\d+$", max_length=64)]


def _require_platform(request: Request, *, execution: bool = False) -> None:
    settings = request.app.state.settings
    if not settings.endpoint_module_platform_enabled or (execution and not settings.endpoint_module_execution_enabled):
        raise HTTPException(status_code=404, detail="Платформа модулей отключена")


def _module_conflict(error: Exception) -> HTTPException:
    return HTTPException(status_code=409, detail="Действие недоступно для текущего состояния модуля")


async def _version(session, key: str, version: str) -> tuple[ModuleDefinition, ModuleVersion]:
    row = (await session.execute(
        select(ModuleDefinition, ModuleVersion)
        .join(ModuleVersion, ModuleVersion.module_definition_id == ModuleDefinition.id)
        .where(ModuleDefinition.module_key == key, ModuleVersion.version == version)
    )).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Версия модуля не найдена")
    return row


async def _audit(session, request: Request, principal: AdminPrincipal, action: str, module_version: ModuleVersion, key: str) -> None:
    await append_audit_event(
        session, actor_kind="admin", actor_identifier=str(principal.user.id),
        action=action, object_kind="module_version", object_identifier=str(module_version.id),
        request_id=audit_request_id(request),
        details={"module_key": key, "version": module_version.version, "state": module_version.state},
    )


@router.get("/module-capabilities", response_model=ConsoleCapabilityCatalogResponse)
async def console_module_capabilities(
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
) -> dict[str, object]:
    _require_platform(request)
    catalog = module_capability_catalog().model_dump(mode="json")
    for item in catalog["items"]:
        item["display_name"] = _CAPABILITY_DISPLAY_NAMES[item["capability"]]
    return {"data": catalog}


@router.get("/modules", response_model=ConsoleModulePageResponse)
async def console_list_modules(
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> dict[str, object]:
    _require_platform(request)
    async with request.app.state.session_provider() as session:
        total = await session.scalar(
            select(func.count()).select_from(ModuleVersion)
            .join(ModuleDefinition, ModuleDefinition.id == ModuleVersion.module_definition_id)
        ) or 0
        rows = (await session.execute(
            select(ModuleDefinition, ModuleVersion)
            .join(ModuleVersion, ModuleVersion.module_definition_id == ModuleDefinition.id)
            .order_by(ModuleDefinition.module_key, ModuleVersion.created_at.desc(), ModuleVersion.id.desc())
            .limit(limit).offset(offset)
        )).all()
    grouped: dict[UUID, tuple[ModuleDefinition, list[dict[str, object]]]] = {}
    for definition, version in rows:
        if definition.id not in grouped:
            grouped[definition.id] = (definition, [])
        grouped[definition.id][1].append({
            "id": str(version.id), "version": version.version,
            "state": version.state, "created_at": version.created_at,
        })
    return {"data": [{
        "module_key": definition.module_key, "display_name": definition.display_name,
        "versions": versions,
    } for definition, versions in grouped.values()], "total": total, "limit": limit, "offset": offset}


@router.get("/modules/{module_key}/versions/{version}", response_model=ConsoleModuleVersionDetailResponse)
async def console_module_version(
    module_key: ModuleKey,
    version: ModuleVersionName,
    request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
    validation_limit: Annotated[int, Query(ge=1, le=50)] = 20,
    validation_offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    lab_limit: Annotated[int, Query(ge=1, le=50)] = 20,
    lab_offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> dict[str, object]:
    _require_platform(request)
    async with request.app.state.session_provider() as session:
        definition, record = await _version(session, module_key, version)
        validations_total = await session.scalar(
            select(func.count()).select_from(ModuleValidationRun)
            .where(ModuleValidationRun.module_version_id == record.id)
        ) or 0
        validations = (await session.execute(
            select(ModuleValidationRun).where(ModuleValidationRun.module_version_id == record.id)
            .order_by(ModuleValidationRun.completed_at.desc(), ModuleValidationRun.id.desc())
            .limit(validation_limit).offset(validation_offset)
        )).scalars().all()
        labs_total = await session.scalar(
            select(func.count()).select_from(ModuleLiveTest)
            .where(ModuleLiveTest.module_version_id == record.id)
        ) or 0
        labs = (await session.execute(
            select(ModuleLiveTest).where(ModuleLiveTest.module_version_id == record.id)
            .order_by(ModuleLiveTest.tested_at.desc(), ModuleLiveTest.id.desc())
            .limit(lab_limit).offset(lab_offset)
        )).scalars().all()
        passed_lab_platforms = sorted(set(await session.scalars(
            select(ModuleLiveTest.platform).where(
                ModuleLiveTest.module_version_id == record.id,
                ModuleLiveTest.status == "passed",
            ).distinct()
        )))
    try:
        view = ModuleVersionViewV1(
            module_key=definition.module_key, display_name=definition.display_name,
            version=record.version, state=record.state, recipe=record.recipe,
        ).model_dump(mode="json")
    except ValidationError as error:
        raise HTTPException(status_code=503, detail="Рецепт модуля недоступен") from error
    return {"data": {
        **view, "id": str(record.id), "created_at": record.created_at,
        "validations_total": validations_total,
        "validation_limit": validation_limit,
        "validation_offset": validation_offset,
        "labs_total": labs_total,
        "lab_limit": lab_limit,
        "lab_offset": lab_offset,
        "passed_lab_platforms": passed_lab_platforms,
        "validations": [{
            "status": item.status, "validator_version": item.validator_version,
            "error_codes": item.error_codes, "warning_codes": item.warning_codes,
            "completed_at": item.completed_at,
        } for item in validations],
        "labs": [{
            "platform": item.platform, "status": item.status,
            "operation_id": str(item.operation_id), "device_id": str(item.endpoint_device_id),
            "tested_at": item.tested_at,
        } for item in labs],
    }}


@router.post("/modules/versions", status_code=201, response_model=ConsoleModuleCreateResponse)
async def console_create_module_version(
    body: ModuleVersionCreateV1,
    request: Request,
    principal: Annotated[AdminPrincipal, Depends(require_admin)],
) -> dict[str, object]:
    _require_platform(request)
    async with request.app.state.session_provider() as session:
        try:
            record = await persist_draft_version(
                session, recipe=body.recipe, display_name=body.display_name, version=body.version,
            )
            await _audit(session, request, principal, "endpoint.module_version_created", record, body.recipe.module_key)
            await session.commit()
        except (ModuleServiceError, ModuleLifecycleError) as error:
            await session.rollback()
            raise _module_conflict(error) from error
        except Exception:
            await session.rollback()
            raise
    return {"data": {"id": str(record.id), "module_key": body.recipe.module_key, "version": record.version, "state": record.state}}


@router.post("/modules/{module_key}/versions/{version}/validate", response_model=ConsoleModuleValidationResponse)
async def console_validate_module_version(
    module_key: ModuleKey, version: ModuleVersionName, request: Request,
    principal: Annotated[AdminPrincipal, Depends(require_admin)],
) -> dict[str, object]:
    _require_platform(request)
    async with request.app.state.session_provider() as session:
        _, record = await _version(session, module_key, version)
        try:
            result = await validate_persisted_module_version(session, record)
            await _audit(session, request, principal, "endpoint.module_validation_completed", record, module_key)
            await session.commit()
        except (ModuleServiceError, ModuleLifecycleError) as error:
            await session.rollback()
            raise _module_conflict(error) from error
        except Exception:
            await session.rollback()
            raise
    return {"data": {
        "status": result.status, "error_codes": result.error_codes,
        "warning_codes": result.warning_codes, "validator_version": result.validator_version,
        "completed_at": result.completed_at,
    }}


async def _transition(request: Request, principal: AdminPrincipal, key: str, version: str, action: str) -> dict[str, object]:
    _require_platform(request)
    async with request.app.state.session_provider() as session:
        _, record = await _version(session, key, version)
        try:
            if action == "accept-labs":
                changed = await accept_persisted_module_labs(session, record)
                audit_action = "endpoint.module_labs_accepted"
            elif action == "publish":
                changed = await publish_persisted_module_version(session, record)
                audit_action = "endpoint.module_published"
            elif action == "deprecate":
                changed = await transition_persisted_version(session, record, "deprecated")
                audit_action = "endpoint.module_deprecated"
            else:
                raise HTTPException(status_code=404)
            await _audit(session, request, principal, audit_action, changed, key)
            await session.commit()
        except (ModuleServiceError, ModuleLifecycleError) as error:
            await session.rollback()
            raise _module_conflict(error) from error
        except Exception:
            await session.rollback()
            raise
    return {"data": {"module_key": key, "version": version, "state": changed.state}}


@router.post("/modules/{module_key}/versions/{version}/accept-labs", response_model=ConsoleModuleTransitionResponse)
async def console_accept_module_labs(module_key: ModuleKey, version: ModuleVersionName, request: Request, principal: Annotated[AdminPrincipal, Depends(require_admin)]) -> dict[str, object]:
    return await _transition(request, principal, module_key, version, "accept-labs")


@router.post("/modules/{module_key}/versions/{version}/publish", response_model=ConsoleModuleTransitionResponse)
async def console_publish_module_version(module_key: ModuleKey, version: ModuleVersionName, request: Request, principal: Annotated[AdminPrincipal, Depends(require_admin)]) -> dict[str, object]:
    return await _transition(request, principal, module_key, version, "publish")


@router.post("/modules/{module_key}/versions/{version}/deprecate", response_model=ConsoleModuleTransitionResponse)
async def console_deprecate_module_version(module_key: ModuleKey, version: ModuleVersionName, request: Request, principal: Annotated[AdminPrincipal, Depends(require_admin)]) -> dict[str, object]:
    return await _transition(request, principal, module_key, version, "deprecate")


@router.post("/modules/{module_key}/versions/{version}/lab-evidence/{operation_id}", response_model=ConsoleModuleLabResponse)
async def console_record_module_lab(
    module_key: ModuleKey, version: ModuleVersionName, operation_id: UUID,
    request: Request, principal: Annotated[AdminPrincipal, Depends(require_admin)],
) -> dict[str, object]:
    _require_platform(request, execution=True)
    async with request.app.state.session_provider() as session:
        _, record = await _version(session, module_key, version)
        try:
            lab = await record_module_live_test(session, record, operation_id=operation_id)
            await _audit(session, request, principal, "endpoint.module_live_test_recorded", record, module_key)
            await session.commit()
        except ModuleServiceError as error:
            await session.rollback()
            raise _module_conflict(error) from error
        except Exception:
            await session.rollback()
            raise
    return {"data": {"platform": lab.platform, "status": lab.status, "tested_at": lab.tested_at}}


@router.get("/modules/{module_key}/versions/{version}/lab-devices", response_model=ConsoleLabDevicePageResponse)
async def console_module_lab_devices(
    module_key: ModuleKey, version: ModuleVersionName, request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> dict[str, object]:
    _require_platform(request, execution=True)
    async with request.app.state.session_provider() as session:
        _, record = await _version(session, module_key, version)
        if record.state != "validated":
            return {"data": [], "total": 0, "limit": limit, "offset": offset}
        try:
            recipe = EndpointRecipeModuleSpecV1.model_validate(record.recipe)
        except ValidationError as error:
            raise HTTPException(status_code=503, detail="Рецепт модуля недоступен") from error
        connections = await request.app.state.gateway_connection_registry.connected()
        compatible_ids = [connection.device_id for connection in connections if (
            connection.platform in recipe.supported_platforms
            and all(step.capability in compatible_module_capabilities(request.app.state.settings, connection) for step in recipe.steps)
        )]
        total = await session.scalar(
            select(func.count()).select_from(Device)
            .where(Device.id.in_(compatible_ids), Device.retired_at.is_(None))
        ) if compatible_ids else 0
        devices = (await session.execute(
            select(Device.id, Device.display_name, Device.device_identifier)
            .where(Device.id.in_(compatible_ids), Device.retired_at.is_(None))
            .order_by(Device.display_name, Device.device_identifier, Device.id)
            .limit(limit).offset(offset)
        )).all() if compatible_ids else []
    return {"data": [{
        "id": str(device_id), "display_name": display_name or identifier,
    } for device_id, display_name, identifier in devices], "total": total, "limit": limit, "offset": offset}


async def _create_operation(
    request: Request, principal: AdminPrincipal, *, device_id: UUID,
    module_key: str, version: str, inputs: dict[str, object],
    idempotency_key: str, mode: str,
) -> dict[str, object]:
    _require_platform(request, execution=True)
    connection = await request.app.state.gateway_connection_registry.get(device_id)
    if connection is None:
        raise HTTPException(status_code=409, detail="Тестовое устройство не в сети")
    settings = request.app.state.settings
    async with request.app.state.session_provider() as session:
        _, record = await _version(session, module_key, version)
        try:
            recipe = EndpointRecipeModuleSpecV1.model_validate(record.recipe)
        except ValidationError as error:
            raise HTTPException(status_code=503, detail="Рецепт модуля недоступен") from error
        available = set(compatible_module_capabilities(settings, connection))
        if connection.platform not in recipe.supported_platforms or any(step.capability not in available for step in recipe.steps):
            raise HTTPException(status_code=409, detail="Модуль несовместим с устройством")
        owner = await session.scalar(select(ServiceClient).where(
            ServiceClient.client_identifier == _OWNER_IDENTIFIER,
            ServiceClient.disabled_at.is_(None),
        ))
        if owner is None:
            raise HTTPException(status_code=503, detail="Внутренний владелец Console не настроен")
        policy = NetworkTargetPolicyV1.from_values(
            allowed_cidrs=settings.endpoint_network_probe_allowed_cidrs,
            allowed_suffixes=settings.endpoint_network_probe_allowed_suffixes,
        )
        try:
            operation, created = await create_module_parent_operation(
                session, service_client_id=owner.id, device_id=device_id,
                module_key=module_key, version=version, inputs=inputs,
                idempotency_key=idempotency_key, network_policy=policy,
                execution_mode="lab" if mode == "lab" else "published",
            )
            if created:
                await append_audit_event(
                    session, actor_kind="admin", actor_identifier=str(principal.user.id),
                    action="endpoint.module_lab_started" if mode == "lab" else "endpoint.module_operation_started",
                    object_kind="endpoint_operation", object_identifier=str(operation.id),
                    request_id=audit_request_id(request),
                    details={"module_key": module_key, "version": version, "device_id": str(device_id)},
                )
            await session.commit()
        except ModuleOperationError as error:
            await session.rollback()
            raise _module_conflict(error) from error
        except Exception:
            await session.rollback()
            raise
    return {"data": {"operation_id": str(operation.id), "status": operation.status, "created": created}}


@router.post("/modules/{module_key}/versions/{version}/lab-operations/{device_id}", status_code=201, response_model=ConsoleModuleOperationCreateResponse)
async def console_start_module_lab(
    module_key: ModuleKey, version: ModuleVersionName, device_id: UUID,
    body: ConsoleModuleLabOperationCreateV1, request: Request,
    principal: Annotated[AdminPrincipal, Depends(require_admin)],
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=8, max_length=128)],
) -> dict[str, object]:
    return await _create_operation(
        request, principal, device_id=device_id, module_key=module_key,
        version=version, inputs=body.inputs, idempotency_key=idempotency_key, mode="lab",
    )


@router.post("/devices/{device_id}/module-operations", status_code=201, response_model=ConsoleModuleOperationCreateResponse)
async def console_run_module(
    device_id: UUID, body: ConsoleModuleOperationCreateV1, request: Request,
    principal: Annotated[AdminPrincipal, Depends(require_admin)],
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=8, max_length=128)],
) -> dict[str, object]:
    return await _create_operation(
        request, principal, device_id=device_id, module_key=body.module_key,
        version=body.version, inputs=body.inputs, idempotency_key=idempotency_key, mode="published",
    )


@router.get("/devices/{device_id}/modules", response_model=ConsoleDeviceModulePageResponse)
async def console_device_modules(
    device_id: UUID, request: Request,
    _: Annotated[AdminPrincipal, Depends(require_admin)],
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> dict[str, object]:
    _require_platform(request)
    connection = await request.app.state.gateway_connection_registry.get(device_id)
    available = set(compatible_module_capabilities(request.app.state.settings, connection))
    async with request.app.state.session_provider() as session:
        exists = await session.scalar(select(Device.id).where(Device.id == device_id, Device.retired_at.is_(None)))
        if exists is None:
            raise HTTPException(status_code=404, detail="Устройство не найдено")
        total = await session.scalar(
            select(func.count()).select_from(ModuleDefinition)
            .join(ModuleVersion, ModuleVersion.module_definition_id == ModuleDefinition.id)
            .where(ModuleVersion.state == "published")
        ) or 0
        rows = (await session.execute(
            select(ModuleDefinition, ModuleVersion)
            .join(ModuleVersion, ModuleVersion.module_definition_id == ModuleDefinition.id)
            .where(ModuleVersion.state == "published")
            .order_by(ModuleDefinition.module_key, ModuleVersion.version.desc(), ModuleVersion.id.desc())
            .limit(limit).offset(offset)
        )).all()
    data = []
    for definition, version in rows:
        try:
            recipe = EndpointRecipeModuleSpecV1.model_validate(version.recipe)
        except ValidationError:
            continue
        compatible = bool(connection and connection.platform in recipe.supported_platforms and all(step.capability in available for step in recipe.steps))
        data.append({
            "module_key": definition.module_key, "display_name": definition.display_name,
            "version": version.version, "compatible": compatible,
            "reason": None if compatible else "Устройство не в сети или capability недоступен",
            "inputs": [item.model_dump(mode="json") for item in recipe.inputs],
        })
    return {"data": data, "total": total, "limit": limit, "offset": offset}
