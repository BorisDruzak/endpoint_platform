"""Closed declarative recipe contract for Endpoint-owned modules."""

from __future__ import annotations

import copy

import pytest
from pydantic import ValidationError

from datetime import UTC, datetime

from endpoint_contracts.modules import (
    EndpointRecipeModuleSpecV1,
    ModuleValidationRunV1,
    ModuleVersionCreateV1,
)
from endpoint_server.modules.recipes import RecipeValidationError, validate_recipe_spec


def _recipe() -> dict[str, object]:
    return {
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


def test_recipe_contract_and_catalog_validation_accept_network_basic_check() -> None:
    recipe = EndpointRecipeModuleSpecV1.model_validate(_recipe())

    validate_recipe_spec(recipe)

    assert [step.step_id for step in recipe.steps] == ["dns", "ping", "tcp"]


def test_module_version_create_contract_requires_semantic_version() -> None:
    payload = {"schema_version": "module_version_create_v1", "display_name": "Network", "version": "1.0.0", "recipe": _recipe()}
    assert ModuleVersionCreateV1.model_validate(payload).version == "1.0.0"
    payload["version"] = "latest"
    with pytest.raises(ValidationError):
        ModuleVersionCreateV1.model_validate(payload)


def test_module_validation_result_contract_is_bounded_and_versioned() -> None:
    outcome = ModuleValidationRunV1.model_validate(
        {
            "schema_version": "module_validation_run_v1",
            "module_key": "network.basic.check",
            "version": "1.0.0",
            "status": "succeeded",
            "error_codes": [],
            "warning_codes": [],
            "completed_at": datetime(2026, 8, 26, tzinfo=UTC),
        }
    )
    assert outcome.schema_version == "module_validation_run_v1"


def test_recipe_contract_rejects_undeclared_executable_fields() -> None:
    payload = _recipe()
    payload["steps"][0]["shell"] = "powershell -Command whoami"  # type: ignore[index]

    with pytest.raises(ValidationError):
        EndpointRecipeModuleSpecV1.model_validate(payload)


def test_recipe_validation_rejects_wrong_input_type_and_parameter_shape() -> None:
    payload = _recipe()
    payload["steps"][2]["parameters"].pop("timeout_ms")  # type: ignore[index]
    recipe = EndpointRecipeModuleSpecV1.model_validate(payload)

    with pytest.raises(RecipeValidationError, match="recipe parameter shape"):
        validate_recipe_spec(recipe)

    wrong_type = _recipe()
    wrong_type["inputs"][1]["value_type"] = "string"  # type: ignore[index]
    recipe = EndpointRecipeModuleSpecV1.model_validate(wrong_type)
    with pytest.raises(RecipeValidationError, match="recipe input type"):
        validate_recipe_spec(recipe)


def test_recipe_validation_rejects_input_for_literal_only_service_key() -> None:
    """A recipe cannot turn an internal service key into caller-controlled input."""
    recipe = EndpointRecipeModuleSpecV1.model_validate(
        {
            "schema_version": "endpoint_recipe_module_v1",
            "module_key": "system.service.check",
            "supported_platforms": ["linux_amd64"],
            "inputs": [{"name": "service_key", "value_type": "string"}],
            "steps": [
                {
                    "step_id": "service",
                    "capability": "system.service_status",
                    "parameters": {
                        "service_key": {"kind": "input", "name": "service_key"}
                    },
                }
            ],
        }
    )

    with pytest.raises(RecipeValidationError, match="input source"):
        validate_recipe_spec(recipe)


def test_recipe_contract_limits_steps_and_rejects_duplicate_step_ids() -> None:
    duplicate = _recipe()
    duplicate["steps"].append(copy.deepcopy(duplicate["steps"][0]))  # type: ignore[index]
    with pytest.raises(ValidationError, match="step_id"):
        EndpointRecipeModuleSpecV1.model_validate(duplicate)

    oversized = _recipe()
    oversized["steps"] = [copy.deepcopy(oversized["steps"][0]) for _ in range(9)]  # type: ignore[index]
    with pytest.raises(ValidationError):
        EndpointRecipeModuleSpecV1.model_validate(oversized)
