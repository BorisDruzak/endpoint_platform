"""Service guards for Endpoint-owned module version creation."""

from __future__ import annotations

from endpoint_contracts.modules import EndpointRecipeModuleSpecV1

from .recipes import RecipeValidationError, validate_recipe_spec


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


__all__ = ["ModuleServiceError", "create_draft_version"]
