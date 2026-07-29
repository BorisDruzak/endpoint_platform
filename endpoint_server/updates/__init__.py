"""Endpoint Platform update rollout control-plane domain API."""

from .errors import (
    UpdateConflict,
    UpdateError,
    UpdateNotFound,
    UpdateStateError,
    UpdateValidationError,
)
from .service import (
    activate_rollout,
    complete_rollout,
    create_rollback_rollout,
    create_rollout,
    pause_rollout,
    recommendation_for_device,
    record_ack,
    record_report,
    register_build,
)

__all__ = [
    "UpdateConflict",
    "UpdateError",
    "UpdateNotFound",
    "UpdateStateError",
    "UpdateValidationError",
    "activate_rollout",
    "complete_rollout",
    "create_rollback_rollout",
    "create_rollout",
    "pause_rollout",
    "recommendation_for_device",
    "record_ack",
    "record_report",
    "register_build",
]
