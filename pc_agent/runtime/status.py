"""Process-local status for the headless runtime lifecycle."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from pc_agent.transport.base import GatewayProtocolIncompatible


class ControlState(str, Enum):
    CONNECTED = "CONTROL_CONNECTED"
    RETRYING = "CONTROL_RETRYING"
    DEGRADED_RECOVERABLE = "CONTROL_DEGRADED_RECOVERABLE"
    TERMINAL_LOCAL = "CONTROL_TERMINAL_LOCAL"


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
    control_state: ControlState = ControlState.RETRYING

    def transition(
        self, phase: RuntimePhase, *, error: BaseException | None = None
    ) -> None:
        self.phase = phase
        self.last_error = None if error is None else type(error).__name__
        if phase is RuntimePhase.RUNNING:
            self.control_state = ControlState.CONNECTED
        elif phase in {RuntimePhase.CREDENTIAL_REJECTED, RuntimePhase.FAILED}:
            self.control_state = ControlState.TERMINAL_LOCAL

    def record_reconnect(self, error: BaseException) -> None:
        self.reconnect_attempts += 1
        self.transition(RuntimePhase.RECONNECTING, error=error)
        self.control_state = (
            ControlState.DEGRADED_RECOVERABLE
            if isinstance(error, GatewayProtocolIncompatible) else ControlState.RETRYING
        )
