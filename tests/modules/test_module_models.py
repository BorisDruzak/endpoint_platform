from __future__ import annotations

from endpoint_server.db.models.modules import MODULE_VERSION_STATES


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
