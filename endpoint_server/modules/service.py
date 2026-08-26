"""Service guards for Endpoint-owned module version creation."""

from __future__ import annotations

from endpoint_contracts.modules import EndpointRecipeModuleSpecV1
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from endpoint_server.db.models.modules import ModuleDefinition, ModuleVersion

from .recipes import RecipeValidationError, validate_recipe_spec
from .lifecycle import transition_module_version


class ModuleServiceError(ValueError):
    """A module mutation failed before any persistence is attempted."""


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


__all__ = ["ModuleServiceError", "create_draft_version", "persist_draft_version", "transition_persisted_version"]
