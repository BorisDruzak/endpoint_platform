"""Endpoint Platform update rollout control-plane domain API."""

from .errors import (
    UpdateConflict,
    UpdateError,
    UpdateNotFound,
    UpdateStateError,
    UpdateValidationError,
)
from .service import (
    cancel_paused_singleton_rollout,
    rollout_cancellation_context,
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
    "cancel_paused_singleton_rollout",
    "rollout_cancellation_context",
    "complete_rollout",
    "create_rollback_rollout",
    "create_rollout",
    "pause_rollout",
    "recommendation_for_device",
    "record_ack",
    "record_report",
    "register_build",
]
