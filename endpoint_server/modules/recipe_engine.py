"""Deterministic expansion of declarative module recipes into typed commands."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from endpoint_contracts.modules import (
    EndpointRecipeModuleSpecV1,
    RecipeInputBindingV1,
    RecipeLiteralBindingV1,
)
from endpoint_contracts.network_primitives import (
    DnsResolveParametersV1,
    NetworkPingParametersV1,
    TcpConnectParametersV1,
)
from pydantic import ValidationError

from .recipes import RecipeValidationError, validate_recipe_spec


class RecipeExecutionError(ValueError):
    """A declarative recipe cannot become bounded typed child commands."""


@dataclass(frozen=True, slots=True)
class RecipeCommandPlanItem:
    sequence: int
    step_id: str
    capability: Literal["dns.resolve", "network.ping", "tcp.connect"]
    parameters: dict[str, str | int]


def build_recipe_command_plan(
    recipe: EndpointRecipeModuleSpecV1,
    inputs: Mapping[str, object],
) -> tuple[RecipeCommandPlanItem, ...]:
    """Resolve declared inputs once, then validate every primitive payload."""
    try:
        validate_recipe_spec(recipe)
    except RecipeValidationError as error:
        raise RecipeExecutionError("module recipe is not executable") from error
    _validate_runtime_inputs(recipe, inputs)

    plan: list[RecipeCommandPlanItem] = []
    for sequence, step in enumerate(recipe.steps):
        parameters = {
            parameter_name: _resolve_binding(binding, inputs)
            for parameter_name, binding in step.parameters.items()
        }
        plan.append(
            RecipeCommandPlanItem(
                sequence=sequence,
                step_id=step.step_id,
                capability=step.capability,
                parameters=_validate_primitive_parameters(step.capability, parameters),
            )
        )
    return tuple(plan)


def _validate_runtime_inputs(
    recipe: EndpointRecipeModuleSpecV1,
    inputs: Mapping[str, object],
) -> None:
    expected = {item.name: item.value_type for item in recipe.inputs}
    if set(inputs) != set(expected):
        raise RecipeExecutionError("module inputs do not exactly match the recipe")
    for name, value_type in expected.items():
        expected_python_type = str if value_type == "string" else int
        if type(inputs[name]) is not expected_python_type:
            raise RecipeExecutionError("module input type does not match the recipe")


def _resolve_binding(
    binding: RecipeInputBindingV1 | RecipeLiteralBindingV1,
    inputs: Mapping[str, object],
) -> str | int:
    if isinstance(binding, RecipeInputBindingV1):
        value = inputs[binding.name]
    elif isinstance(binding, RecipeLiteralBindingV1):
        value = binding.value
    else:
        raise RecipeExecutionError("module parameter binding is not supported")
    if type(value) not in {str, int}:
        raise RecipeExecutionError("module parameter is not a primitive value")
    return value


def _validate_primitive_parameters(
    capability: str,
    parameters: dict[str, str | int],
) -> dict[str, str | int]:
    try:
        if capability == "dns.resolve":
            model = DnsResolveParametersV1.model_validate(
                {"schema_version": "dns_resolve_parameters_v1", **parameters}
            )
        elif capability == "network.ping":
            model = NetworkPingParametersV1.model_validate(
                {"schema_version": "network_ping_parameters_v1", **parameters}
            )
        elif capability == "tcp.connect":
            model = TcpConnectParametersV1.model_validate(
                {"schema_version": "tcp_connect_parameters_v1", **parameters}
            )
        else:
            raise RecipeExecutionError("module capability is not supported")
    except ValidationError as error:
        raise RecipeExecutionError("module inputs do not satisfy primitive bounds") from error
    validated = model.model_dump(mode="json", exclude={"schema_version"})
    return {key: value for key, value in validated.items() if type(value) in {str, int}}


__all__ = [
    "RecipeCommandPlanItem",
    "RecipeExecutionError",
    "build_recipe_command_plan",
]
