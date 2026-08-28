"""Service guards for Endpoint-owned module version creation."""

from __future__ import annotations

from datetime import UTC, datetime
import json
from uuid import UUID

from endpoint_contracts.modules import EndpointRecipeModuleSpecV1
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_server.db.models.operations import EndpointOperation, ModuleOperationStep
from endpoint_server.db.models.modules import (
    ModuleDefinition,
    ModuleLiveTest,
    ModuleValidationRun,
    ModuleVersion,
)

from .recipes import RecipeValidationError, validate_recipe_spec
from .lifecycle import transition_module_version


class ModuleServiceError(ValueError):
    """A module mutation failed before any persistence is attempted."""


STATIC_RECIPE_VALIDATOR_VERSION = "endpoint_recipe_static_v1"
_SAFE_LAB_SNAPSHOT_MAX_BYTES = 128 * 1024
_FORBIDDEN_LAB_SNAPSHOT_KEYS = frozenset(
    {
        "command_payload",
        "raw_command",
        "raw_stderr",
        "raw_stdout",
        "recipe",
        "user_function_body",
    }
)


def create_draft_version(recipe: EndpointRecipeModuleSpecV1 | None) -> str:
    """Validate the only permitted draft payload before database composition."""
    if recipe is None:
        raise ModuleServiceError("recipe is required")
    try:
        validate_recipe_spec(recipe)
    except RecipeValidationError as error:
        raise ModuleServiceError("recipe is not valid") from error
    return "draft"


async def persist_draft_version(
    session: AsyncSession,
    *,
    recipe: EndpointRecipeModuleSpecV1,
    display_name: str,
    version: str,
) -> ModuleVersion:
    """Compose one immutable draft version without committing the caller transaction."""
    create_draft_version(recipe)
    definition = await session.scalar(
        select(ModuleDefinition).where(ModuleDefinition.module_key == recipe.module_key)
    )
    if definition is None:
        definition = ModuleDefinition(
            module_key=recipe.module_key,
            display_name=display_name,
        )
        session.add(definition)
        await session.flush()
    existing = await session.scalar(
        select(ModuleVersion).where(
            ModuleVersion.module_definition_id == definition.id,
            ModuleVersion.version == version,
        )
    )
    if existing is not None:
        raise ModuleServiceError("module version already exists")
    module_version = ModuleVersion(
        module_definition_id=definition.id,
        version=version,
        recipe=recipe.model_dump(mode="json"),
        state="draft",
    )
    session.add(module_version)
    await session.flush()
    return module_version


async def transition_persisted_version(
    session: AsyncSession, module_version: ModuleVersion, target_state: str
) -> ModuleVersion:
    """Move lifecycle state only; recipe/version fields remain immutable."""
    module_version.state = transition_module_version(module_version.state, target_state)
    await session.flush()
    return module_version


async def validate_persisted_module_version(
    session: AsyncSession,
    module_version: ModuleVersion,
    *,
    completed_at: datetime | None = None,
) -> ModuleValidationRun:
    """Persist one bounded static validation outcome and its lifecycle transition."""
    if module_version.state not in {"draft", "validation_failed"}:
        raise ModuleServiceError(
            "module version cannot be validated in its current state"
        )

    error_codes: list[str] = []
    try:
        recipe = EndpointRecipeModuleSpecV1.model_validate(module_version.recipe)
    except ValidationError:
        error_codes.append("recipe_contract_invalid")
    else:
        try:
            validate_recipe_spec(recipe)
        except RecipeValidationError:
            error_codes.append("recipe_catalog_invalid")

    validation_status = "failed" if error_codes else "succeeded"
    target_state = "validation_failed" if error_codes else "validated"
    if module_version.state != target_state:
        module_version.state = transition_module_version(
            module_version.state, target_state
        )

    validation_run = ModuleValidationRun(
        module_version_id=module_version.id,
        validator_version=STATIC_RECIPE_VALIDATOR_VERSION,
        status=validation_status,
        error_codes=error_codes,
        warning_codes=[],
        completed_at=completed_at or datetime.now(UTC),
    )
    session.add(validation_run)
    await session.flush()
    return validation_run


def _declared_platforms(module_version: ModuleVersion) -> frozenset[str]:
    try:
        recipe = EndpointRecipeModuleSpecV1.model_validate(module_version.recipe)
    except ValidationError as error:
        raise ModuleServiceError("module version recipe is invalid") from error
    return frozenset(recipe.supported_platforms)


def _validate_safe_lab_snapshot(snapshot: dict[str, object]) -> None:
    if not isinstance(snapshot, dict):
        raise ModuleServiceError("lab result snapshot must be an object")
    if _contains_forbidden_lab_snapshot_key(snapshot):
        raise ModuleServiceError("lab result snapshot contains forbidden data")
    try:
        encoded = json.dumps(snapshot, separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError) as error:
        raise ModuleServiceError(
            "lab result snapshot must be JSON serializable"
        ) from error
    if len(encoded.encode("utf-8")) > _SAFE_LAB_SNAPSHOT_MAX_BYTES:
        raise ModuleServiceError("lab result snapshot exceeds the safe size limit")


def _contains_forbidden_lab_snapshot_key(value: object) -> bool:
    if isinstance(value, dict):
        return any(
            str(key).lower() in _FORBIDDEN_LAB_SNAPSHOT_KEYS
            or _contains_forbidden_lab_snapshot_key(child)
            for key, child in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_forbidden_lab_snapshot_key(child) for child in value)
    return False


async def record_module_live_test(
    session: AsyncSession,
    module_version: ModuleVersion,
    *,
    operation_id: UUID,
    tested_at: datetime | None = None,
) -> ModuleLiveTest:
    """Record bounded lab evidence from an Endpoint-owned module operation."""
    if module_version.state not in {"validated", "lab_accepted"}:
        raise ModuleServiceError("module version is not ready for lab acceptance")
    operation = await session.scalar(
        select(EndpointOperation).where(EndpointOperation.id == operation_id)
    )
    execution_mode = (
        operation.parameters.get("execution_mode")
        if operation is not None and isinstance(operation.parameters, dict)
        else None
    )
    platform = (
        operation.parameters.get("execution_platform")
        if operation is not None and isinstance(operation.parameters, dict)
        else None
    )
    if (
        operation is None
        or operation.capability != "endpoint.module.recipe"
        or operation.module_version_id != module_version.id
        or execution_mode != "lab"
        or platform not in {"linux_amd64", "windows_amd64"}
        or platform not in _declared_platforms(module_version)
        or operation.status != "succeeded"
        or operation.completed_at is None
    ):
        raise ModuleServiceError(
            "lab operation is not a matching terminal module operation"
        )
    steps = (
        await session.scalars(
            select(ModuleOperationStep)
            .where(ModuleOperationStep.operation_id == operation.id)
            .order_by(ModuleOperationStep.sequence)
        )
    ).all()
    expected_step_count = operation.expected_step_count
    if (
        isinstance(expected_step_count, bool)
        or not isinstance(expected_step_count, int)
        or not 1 <= expected_step_count <= 8
        or len(steps) != expected_step_count
        or [step.sequence for step in steps] != list(range(expected_step_count))
        or any(step.status != "succeeded" for step in steps)
    ):
        raise ModuleServiceError("lab operation steps are not complete")
    safe_result_snapshot = {
        "schema_version": "module_live_test_snapshot_v1",
        "operation_status": operation.status,
        "steps": [
            {
                "sequence": step.sequence,
                "capability": step.capability,
                "status": step.status,
                "error_code": step.error_code,
                "safe_result": step.safe_result_json,
            }
            for step in steps
        ],
    }
    _validate_safe_lab_snapshot(safe_result_snapshot)
    live_test = ModuleLiveTest(
        module_version_id=module_version.id,
        platform=platform,
        endpoint_device_id=operation.device_id,
        operation_id=operation_id,
        status="passed",
        safe_result_snapshot=safe_result_snapshot,
        tested_at=tested_at or datetime.now(UTC),
    )
    session.add(live_test)
    await session.flush()
    return live_test


async def _missing_passed_lab_platforms(
    session: AsyncSession,
    module_version: ModuleVersion,
) -> frozenset[str]:
    declared = _declared_platforms(module_version)
    passed = frozenset(
        await session.scalars(
            select(ModuleLiveTest.platform).where(
                ModuleLiveTest.module_version_id == module_version.id,
                ModuleLiveTest.status == "passed",
            )
        )
    )
    return declared - passed


async def accept_persisted_module_labs(
    session: AsyncSession,
    module_version: ModuleVersion,
) -> ModuleVersion:
    """Accept a validated version only when each declared platform passed lab."""
    if module_version.state != "validated":
        raise ModuleServiceError("module version is not ready for lab acceptance")
    if await _missing_passed_lab_platforms(session, module_version):
        raise ModuleServiceError("module version lacks required passed lab evidence")
    return await transition_persisted_version(session, module_version, "lab_accepted")


async def publish_persisted_module_version(
    session: AsyncSession,
    module_version: ModuleVersion,
) -> ModuleVersion:
    """Publish only a lab-accepted version that still has complete evidence."""
    if module_version.state != "lab_accepted":
        raise ModuleServiceError("module version is not ready for publication")
    if await _missing_passed_lab_platforms(session, module_version):
        raise ModuleServiceError("module version lacks required passed lab evidence")
    return await transition_persisted_version(session, module_version, "published")


__all__ = [
    "ModuleServiceError",
    "STATIC_RECIPE_VALIDATOR_VERSION",
    "accept_persisted_module_labs",
    "create_draft_version",
    "persist_draft_version",
    "publish_persisted_module_version",
    "record_module_live_test",
    "transition_persisted_version",
    "validate_persisted_module_version",
]
