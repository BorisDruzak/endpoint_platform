from __future__ import annotations

import re

from sqlalchemy import CheckConstraint

from endpoint_contracts.capabilities import MODULE_CAPABILITY_REGISTRY
from endpoint_server.db.models.operations import (
    ENDPOINT_OPERATION_CAPABILITIES,
    MODULE_OPERATION_STEP_STATUSES,
    EndpointOperation,
    ModuleOperationStep,
)


def test_module_parent_and_step_models_have_closed_runtime_shape() -> None:
    assert ENDPOINT_OPERATION_CAPABILITIES == (
        "context.diagnostic.collect",
        "endpoint.module.recipe",
    )
    assert MODULE_OPERATION_STEP_STATUSES == (
        "queued",
        "delivered",
        "acknowledged",
        "running",
        "succeeded",
        "failed",
        "canceled",
        "expired",
    )
    assert {column.name for column in EndpointOperation.__table__.columns} >= {
        "module_version_id",
        "module_inputs",
        "expected_step_count",
    }
    assert {column.name for column in ModuleOperationStep.__table__.columns} == {
        "id",
        "created_at",
        "operation_id",
        "sequence",
        "recipe_step_key",
        "capability",
        "status",
        "command_id",
        "safe_result_json",
        "error_code",
        "started_at",
        "completed_at",
    }


def test_module_step_persistence_accepts_every_canonical_executable_capability() -> None:
    constraint = next(
        item
        for item in ModuleOperationStep.__table__.constraints
        if isinstance(item, CheckConstraint)
        and item.name == "ck_endpoint_operation_steps_capability"
    )
    allowed = set(re.findall(r"'([^']+)'", str(constraint.sqltext)))
    assert allowed == set(MODULE_CAPABILITY_REGISTRY)
