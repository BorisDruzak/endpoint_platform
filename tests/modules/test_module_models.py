from __future__ import annotations

from endpoint_server.db.models.modules import (
    MODULE_LIVE_TEST_STATUSES,
    MODULE_VALIDATION_RUN_STATUSES,
    MODULE_VERSION_STATES,
    ModuleLiveTest,
    ModuleValidationRun,
)


def test_module_version_lifecycle_is_closed_and_immutable_states_are_declared() -> None:
    assert MODULE_VERSION_STATES == (
        "draft",
        "validation_failed",
        "validated",
        "lab_accepted",
        "published",
        "deprecated",
        "revoked",
    )


def test_module_evidence_models_expose_only_closed_terminal_statuses() -> None:
    assert MODULE_VALIDATION_RUN_STATUSES == ("succeeded", "failed")
    assert MODULE_LIVE_TEST_STATUSES == ("passed", "failed")
    assert {column.name for column in ModuleValidationRun.__table__.columns} == {
        "id",
        "created_at",
        "module_version_id",
        "validator_version",
        "status",
        "error_codes",
        "warning_codes",
        "completed_at",
    }
    assert {column.name for column in ModuleLiveTest.__table__.columns} == {
        "id",
        "created_at",
        "module_version_id",
        "platform",
        "endpoint_device_id",
        "operation_id",
        "status",
        "safe_result_snapshot",
        "tested_at",
    }
