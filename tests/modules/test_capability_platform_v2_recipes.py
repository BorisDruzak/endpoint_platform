"""Every published input descriptor can be used by a declarative recipe."""

from __future__ import annotations

import pytest
import json
from pathlib import Path

from endpoint_contracts.capabilities import MODULE_CAPABILITY_REGISTRY
from endpoint_contracts.modules import EndpointRecipeModuleSpecV1, ModuleVersionCreateV1
from endpoint_server.modules.recipes import validate_recipe_spec


def _literal(descriptor):
    if descriptor.enum_values:
        return descriptor.enum_values[0]
    if descriptor.value_type == "integer":
        return descriptor.minimum or 1
    return "Example"


@pytest.mark.parametrize(
    ("capability", "input_name"),
    [
        (capability, parameter.name)
        for capability, entry in MODULE_CAPABILITY_REGISTRY.items()
        if entry.metadata.minimum_agent_version == "3.2.67"
        for parameter in entry.metadata.parameters
        if "input" in parameter.allowed_sources
    ],
)
def test_new_capability_accepts_each_declared_recipe_input(capability: str, input_name: str) -> None:
    entry = MODULE_CAPABILITY_REGISTRY[capability]
    selected = next(item for item in entry.metadata.parameters if item.name == input_name)
    recipe = EndpointRecipeModuleSpecV1.model_validate({
        "schema_version": "endpoint_recipe_module_v1",
        "module_key": "capability.input.check",
        "supported_platforms": entry.metadata.platforms,
        "inputs": [{"name": input_name, "value_type": "integer" if selected.value_type == "integer" else "string"}],
        "steps": [{
            "step_id": "probe",
            "capability": capability,
            "parameters": {
                parameter.name: (
                    {"kind": "input", "name": input_name}
                    if parameter.name == input_name else {"kind": "literal", "value": _literal(parameter)}
                )
                for parameter in entry.metadata.parameters
            },
        }],
    })
    validate_recipe_spec(recipe)


def test_four_acceptance_module_versions_are_catalog_valid() -> None:
    path = Path(__file__).resolve().parents[2] / "docs" / "verification" / "capability-platform-v2-recipes.json"
    payloads = json.loads(path.read_text(encoding="utf-8"))
    versions = [ModuleVersionCreateV1.model_validate(payload) for payload in payloads]
    assert {version.recipe.module_key for version in versions} == {
        "print.health.check", "software.installation.check",
        "system.quick.check", "process.presence.check",
    }
    for version in versions:
        validate_recipe_spec(version.recipe)
        for step in version.recipe.steps:
            supported = MODULE_CAPABILITY_REGISTRY[step.capability].metadata.platforms
            assert set(version.recipe.supported_platforms) <= set(supported)
