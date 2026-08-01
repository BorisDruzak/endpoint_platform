"""Process-local status for the headless runtime lifecycle."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RuntimePhase(str, Enum):
    CREATED = "created"
    STARTING = "starting"
    CONNECTING = "connecting"
    RUNNING = "running"
    RECONNECTING = "reconnecting"
    STOPPING = "stopping"
    STOPPED = "stopped"
    UPDATE_PENDING = "update_pending"
    CREDENTIAL_REJECTED = "credential_rejected"
    FAILED = "failed"


@dataclass(slots=True)
class RuntimeStatus:
    phase: RuntimePhase = RuntimePhase.CREATED
    reconnect_attempts: int = 0
    last_error: str | None = None

    def transition(
        self, phase: RuntimePhase, *, error: BaseException | None = None
    ) -> None:
        self.phase = phase
        self.last_error = None if error is None else type(error).__name__

    def record_reconnect(self, error: BaseException) -> None:
        self.reconnect_attempts += 1
        self.transition(RuntimePhase.RECONNECTING, error=error)
