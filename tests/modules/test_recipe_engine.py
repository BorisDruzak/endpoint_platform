from __future__ import annotations

import pytest

from endpoint_contracts.modules import EndpointRecipeModuleSpecV1
from endpoint_server.modules.recipe_engine import (
    RecipeExecutionError,
    build_recipe_command_plan,
)


def _recipe() -> EndpointRecipeModuleSpecV1:
    return EndpointRecipeModuleSpecV1.model_validate(
        {
            "schema_version": "endpoint_recipe_module_v1",
            "module_key": "network.basic.check",
            "supported_platforms": ["linux_amd64", "windows_amd64"],
            "inputs": [
                {"name": "target", "value_type": "string"},
                {"name": "port", "value_type": "integer"},
            ],
            "steps": [
                {
                    "step_id": "dns",
                    "capability": "dns.resolve",
                    "parameters": {
                        "target": {"kind": "input", "name": "target"},
                        "family": {"kind": "literal", "value": "any"},
                    },
                },
                {
                    "step_id": "ping",
                    "capability": "network.ping",
                    "parameters": {
                        "target": {"kind": "input", "name": "target"},
                        "count": {"kind": "literal", "value": 2},
                        "timeout_ms": {"kind": "literal", "value": 1000},
                    },
                },
                {
                    "step_id": "tcp",
                    "capability": "tcp.connect",
                    "parameters": {
                        "target": {"kind": "input", "name": "target"},
                        "port": {"kind": "input", "name": "port"},
                        "timeout_ms": {"kind": "literal", "value": 1000},
                    },
                },
            ],
        }
    )


def test_recipe_engine_expands_declared_inputs_into_fixed_typed_commands() -> None:
    commands = build_recipe_command_plan(
        _recipe(),
        {"target": "api.example.test", "port": 443},
    )

    assert [(item.sequence, item.step_id, item.capability) for item in commands] == [
        (0, "dns", "dns.resolve"),
        (1, "ping", "network.ping"),
        (2, "tcp", "tcp.connect"),
    ]
    assert commands[0].parameters == {"target": "api.example.test", "family": "any"}
    assert commands[1].parameters == {
        "target": "api.example.test",
        "count": 2,
        "timeout_ms": 1000,
    }
    assert commands[2].parameters == {
        "target": "api.example.test",
        "port": 443,
        "timeout_ms": 1000,
    }


@pytest.mark.parametrize(
    "inputs",
    [
        {"target": "api.example.test"},
        {"target": "api.example.test", "port": 443, "extra": "blocked"},
        {"target": "api.example.test", "port": True},
        {"target": "https://unsafe.example.test", "port": 443},
    ],
)
def test_recipe_engine_rejects_incomplete_or_invalid_runtime_inputs(
    inputs: dict[str, object],
) -> None:
    with pytest.raises(RecipeExecutionError):
        build_recipe_command_plan(_recipe(), inputs)
