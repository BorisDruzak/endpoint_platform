"""Static catalog validation for bounded declarative module recipes."""

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


class RecipeValidationError(ValueError):
    """Stable server-side rejection of a declarative module recipe."""


@dataclass(frozen=True, slots=True)
class _CatalogEntry:
    parameters: Mapping[str, Literal["string", "integer"]]


_CAPABILITY_CATALOG: Mapping[str, _CatalogEntry] = {
    "dns.resolve": _CatalogEntry({"target": "string", "family": "string"}),
    "network.ping": _CatalogEntry(
        {"target": "string", "count": "integer", "timeout_ms": "integer"}
    ),
    "tcp.connect": _CatalogEntry(
        {"target": "string", "port": "integer", "timeout_ms": "integer"}
    ),
}


def validate_recipe_spec(recipe: EndpointRecipeModuleSpecV1) -> None:
    """Reject any recipe that cannot expand to a fixed typed primitive command."""
    input_types = {item.name: item.value_type for item in recipe.inputs}
    for step in recipe.steps:
        catalog_entry = _CAPABILITY_CATALOG[step.capability]
        if set(step.parameters) != set(catalog_entry.parameters):
            raise RecipeValidationError("recipe parameter shape is not catalog-defined")
        for parameter_name, expected_type in catalog_entry.parameters.items():
            binding = step.parameters[parameter_name]
            if isinstance(binding, RecipeInputBindingV1):
                if input_types.get(binding.name) != expected_type:
                    raise RecipeValidationError("recipe input type does not match capability")
            elif isinstance(binding, RecipeLiteralBindingV1):
                if type(binding.value) is not _python_type_for(expected_type):
                    raise RecipeValidationError("recipe literal type does not match capability")
            else:
                raise RecipeValidationError("recipe binding is not supported")
        _validate_literal_parameter_bounds(step.capability, step.parameters)


def _python_type_for(value_type: Literal["string", "integer"]) -> type[str] | type[int]:
    return str if value_type == "string" else int


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
        if capability == "dns.resolve":
            DnsResolveParametersV1(
                schema_version="dns_resolve_parameters_v1", **values
            )
        elif capability == "network.ping":
            NetworkPingParametersV1(
                schema_version="network_ping_parameters_v1", **values
            )
        elif capability == "tcp.connect":
            TcpConnectParametersV1(
                schema_version="tcp_connect_parameters_v1", **values
            )
        else:
            raise RecipeValidationError("recipe capability is not catalog-defined")
    except ValueError as error:
        raise RecipeValidationError("recipe literal does not satisfy primitive bounds") from error


def _placeholder_for_input(parameter_name: str) -> str | int:
    return {
        "target": "api.example.test",
        "family": "any",
        "count": 1,
        "timeout_ms": 1000,
        "port": 443,
    }[parameter_name]


__all__ = ["RecipeValidationError", "validate_recipe_spec"]
