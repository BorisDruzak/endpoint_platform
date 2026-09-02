"""Static catalog validation for bounded declarative module recipes."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal

from endpoint_contracts.capabilities import (
    module_capability_descriptor,
    validate_module_capability_parameters,
)
from endpoint_contracts.modules import (
    EndpointRecipeModuleSpecV1,
    RecipeInputBindingV1,
    RecipeLiteralBindingV1,
)
class RecipeValidationError(ValueError):
    """Stable server-side rejection of a declarative module recipe."""


def validate_recipe_spec(recipe: EndpointRecipeModuleSpecV1) -> None:
    """Reject any recipe that cannot expand to a fixed typed primitive command."""
    input_types = {item.name: item.value_type for item in recipe.inputs}
    for step in recipe.steps:
        catalog_entry = module_capability_descriptor(step.capability)
        parameter_descriptors = catalog_entry.metadata.parameters
        if set(step.parameters) != {
            parameter_descriptor.name for parameter_descriptor in parameter_descriptors
        }:
            raise RecipeValidationError("recipe parameter shape is not catalog-defined")
        for parameter_descriptor in parameter_descriptors:
            binding = step.parameters[parameter_descriptor.name]
            if isinstance(binding, RecipeInputBindingV1):
                if "input" not in parameter_descriptor.allowed_sources:
                    raise RecipeValidationError("recipe input source is not catalog-defined")
                if input_types.get(binding.name) != _recipe_input_type(parameter_descriptor.value_type):
                    raise RecipeValidationError("recipe input type does not match capability")
            elif isinstance(binding, RecipeLiteralBindingV1):
                if "literal" not in parameter_descriptor.allowed_sources:
                    raise RecipeValidationError("recipe literal source is not catalog-defined")
                if type(binding.value) is not _python_type_for(
                    _recipe_input_type(parameter_descriptor.value_type)
                ):
                    raise RecipeValidationError("recipe literal type does not match capability")
            else:
                raise RecipeValidationError("recipe binding is not supported")
        _validate_literal_parameter_bounds(step.capability, step.parameters)


def _python_type_for(value_type: Literal["string", "integer"]) -> type[str] | type[int]:
    return str if value_type == "string" else int


def _recipe_input_type(value_type: Literal["string", "integer", "enum"]) -> Literal["string", "integer"]:
    return "string" if value_type == "enum" else value_type


def _validate_literal_parameter_bounds(
    capability: str,
    parameters: Mapping[str, RecipeInputBindingV1 | RecipeLiteralBindingV1],
) -> None:
    """Run primitive DTO bounds for literals without inventing dynamic execution."""
    values = {
        name: (
            binding.value
            if isinstance(binding, RecipeLiteralBindingV1)
            else _placeholder_for_input(name)
        )
        for name, binding in parameters.items()
    }
    try:
        validate_module_capability_parameters(capability, values)
    except ValueError as error:
        raise RecipeValidationError("recipe literal does not satisfy primitive bounds") from error


def _placeholder_for_input(parameter_name: str) -> str | int:
    return {
        "target": "api.example.test",
        "family": "any",
        "count": 1,
        "timeout_ms": 1000,
        "port": 443,
        "service_key": "endpoint_agent",
    }[parameter_name]


__all__ = ["RecipeValidationError", "validate_recipe_spec"]
