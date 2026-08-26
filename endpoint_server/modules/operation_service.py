"""Transactional creation of Endpoint-owned declarative module operations."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import ValidationError

from endpoint_contracts.modules import EndpointRecipeModuleSpecV1
from endpoint_server.audit.service import append_audit_event
from endpoint_server.db.models import Device, EndpointOperation, ServiceClient
from endpoint_server.db.models.modules import ModuleDefinition, ModuleVersion
from endpoint_server.db.models.operations import ModuleOperationStep
from endpoint_server.policy.network_targets import (
    NetworkTargetPolicyError,
    NetworkTargetPolicyV1,
)

from .recipe_engine import RecipeExecutionError, build_recipe_command_plan


MODULE_OPERATION_TTL = timedelta(seconds=90)


class ModuleOperationError(ValueError):
    code = "endpoint_module_operation_invalid"


class ModuleOperationConflict(ModuleOperationError):
    code = "endpoint_module_operation_idempotency_conflict"


class ModuleOperationNotFound(ModuleOperationError):
    code = "endpoint_module_operation_not_found"


def _require_uuid(value: UUID | str, name: str) -> UUID:
    try:
        return value if isinstance(value, UUID) else UUID(value)
    except (TypeError, ValueError, AttributeError) as error:
        raise ModuleOperationError(f"{name} must be a UUID") from error


def _require_now(value: datetime | None) -> datetime:
    now = value or datetime.now(UTC)
    if now.utcoffset() is None:
        raise ModuleOperationError("module operation timestamp must be timezone-aware")
    return now.astimezone(UTC)


def _require_idempotency_key(value: str) -> str:
    if (
        not isinstance(value, str)
        or not 8 <= len(value) <= 128
        or value != value.strip()
        or not value.isprintable()
    ):
        raise ModuleOperationError("module operation idempotency key is invalid")
    return value


async def create_module_parent_operation(
    session: AsyncSession,
    *,
    service_client_id: UUID | str,
    device_id: UUID | str,
    module_key: str,
    version: str,
    inputs: Mapping[str, object],
    idempotency_key: str,
    network_policy: NetworkTargetPolicyV1,
    execution_mode: Literal["published", "lab"] = "published",
    now: datetime | None = None,
) -> tuple[EndpointOperation, bool]:
    """Persist a parent and every queued typed step before gateway delivery."""
    client_id = _require_uuid(service_client_id, "service client id")
    checked_device_id = _require_uuid(device_id, "device id")
    checked_key = _require_idempotency_key(idempotency_key)
    occurred_at = _require_now(now)
    client = await session.scalar(
        select(ServiceClient).where(
            ServiceClient.id == client_id,
            ServiceClient.disabled_at.is_(None),
        )
    )
    if client is None:
        raise ModuleOperationNotFound("active service client was not found")
    device = await session.scalar(
        select(Device).where(
            Device.id == checked_device_id, Device.retired_at.is_(None)
        )
    )
    if device is None:
        raise ModuleOperationNotFound("active device was not found")
    module_version = await session.scalar(
        select(ModuleVersion)
        .join(ModuleDefinition)
        .where(
            ModuleDefinition.module_key == module_key,
            ModuleVersion.version == version,
        )
    )
    expected_state = "published" if execution_mode == "published" else "validated"
    if execution_mode not in {"published", "lab"}:
        raise ModuleOperationError("module operation execution mode is invalid")
    if module_version is None or module_version.state != expected_state:
        raise ModuleOperationNotFound(
            "module version is not executable in the requested mode"
        )
    try:
        recipe = EndpointRecipeModuleSpecV1.model_validate(module_version.recipe)
        plan = build_recipe_command_plan(recipe, inputs)
    except (RecipeExecutionError, ValidationError) as error:
        raise ModuleOperationError("module operation inputs are invalid") from error
    try:
        for item in plan:
            target = item.parameters.get("target")
            if not isinstance(target, str):
                raise ModuleOperationError("module operation target is invalid")
            network_policy.require_allowed(target)
    except NetworkTargetPolicyError as error:
        raise ModuleOperationError("module operation target is denied") from error

    existing = await session.scalar(
        select(EndpointOperation).where(
            EndpointOperation.requested_by_service_client_id == client_id,
            EndpointOperation.idempotency_key == checked_key,
        )
    )
    normalized_inputs = dict(inputs)
    if existing is not None:
        if (
            existing.capability != "endpoint.module.recipe"
            or existing.device_id != checked_device_id
            or existing.module_version_id != module_version.id
            or existing.module_inputs != normalized_inputs
            or existing.parameters != {"execution_mode": execution_mode}
        ):
            raise ModuleOperationConflict(
                "idempotency key owns a different module operation"
            )
        return existing, False

    operation = EndpointOperation(
        id=uuid4(),
        created_at=occurred_at,
        requested_by_service_client_id=client_id,
        device_id=checked_device_id,
        idempotency_key=checked_key,
        capability="endpoint.module.recipe",
        parameters={"execution_mode": execution_mode},
        correlation=None,
        status="queued",
        deadline_at=occurred_at + MODULE_OPERATION_TTL,
        completed_at=None,
        context_collection_id=None,
        command_id=None,
        module_version_id=module_version.id,
        module_inputs=normalized_inputs,
    )
    session.add(operation)
    for item in plan:
        session.add(
            ModuleOperationStep(
                id=uuid4(),
                created_at=occurred_at,
                operation_id=operation.id,
                sequence=item.sequence,
                recipe_step_key=item.step_id,
                capability=item.capability,
                status="queued",
                command_id=None,
                safe_result_json=None,
                error_code=None,
                started_at=None,
                completed_at=None,
            )
        )
    await append_audit_event(
        session,
        actor_kind="service",
        actor_identifier=client.client_identifier,
        action="endpoint.module_operation_created",
        object_kind="endpoint_operation",
        object_identifier=str(operation.id),
        request_id=f"module-operation-{operation.id.hex}",
        details={
            "module_key": module_key,
            "module_version": version,
            "device_id": device.id,
            "step_count": len(plan),
            "execution_mode": execution_mode,
        },
        occurred_at=occurred_at,
    )
    await session.flush()
    return operation, True


__all__ = [
    "MODULE_OPERATION_TTL",
    "ModuleOperationConflict",
    "ModuleOperationError",
    "ModuleOperationNotFound",
    "create_module_parent_operation",
]
