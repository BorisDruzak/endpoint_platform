"""Lifecycle primitives shared by the neutral runtime application."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from endpoint_contracts import AgentCommandAckV1, AgentCommandV1, AgentResultV1
from pc_agent.transport.base import (
    GatewayCredentialRejected,
    GatewayIdle,
    GatewayRetryableError,
    GatewayTerminalError,
    GatewayTransport,
)
from pc_agent.transport.protocol import GatewayInboundV1, compatibility_agent_hello
from pc_agent.version import EXIT_UPDATE_PENDING

from .status import RuntimePhase, RuntimeStatus


CredentialRejected = GatewayCredentialRejected
RetryableTransportError = GatewayRetryableError
TerminalTransportError = GatewayTerminalError


@dataclass(frozen=True, slots=True)
class ContinueAfter:
    """A completed transport attempt requests another attempt after a delay."""

    delay: float = 0.0

    def __post_init__(self) -> None:
        if self.delay < 0:
            raise ValueError("transport retry delay must not be negative")


class RuntimeExecutor(Protocol):
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def execute(self, command: AgentCommandV1) -> AgentResultV1: ...


@dataclass(frozen=True, slots=True)
class RuntimeDependencies:
    load_credential: Callable[[object], str]
    create_executor: Callable[[], RuntimeExecutor]
    create_transport: Callable[[object, str, RuntimeExecutor], GatewayTransport]
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    reconnect_delay: float = 5.0


class RuntimeLifecycle:
    """Start, reconnect, and stop neutral runtime components in one place."""

    def __init__(
        self,
        settings: object,
        dependencies: RuntimeDependencies,
        status: RuntimeStatus,
    ) -> None:
        self._settings = settings
        self._dependencies = dependencies
        self._status = status

    async def run(self) -> int:
        self._status.transition(RuntimePhase.STARTING)
        try:
            credential = self._dependencies.load_credential(self._settings)
        except CredentialRejected as error:
            self._status.transition(RuntimePhase.CREDENTIAL_REJECTED, error=error)
            return 75
        except Exception as error:
            self._status.transition(RuntimePhase.FAILED, error=error)
            return 1

        try:
            executor = self._dependencies.create_executor()
        except Exception as error:
            self._status.transition(RuntimePhase.FAILED, error=error)
            return 1
        executor_started = False
        terminal_phase: RuntimePhase | None = None
        try:
            await executor.start()
            executor_started = True
            while True:
                transport = self._dependencies.create_transport(
                    self._settings, credential, executor
                )
                next_delay: float | None = None
                try:
                    self._status.transition(RuntimePhase.CONNECTING)
                    await transport.connect(compatibility_agent_hello())
                    inbound = await transport.receive()
                    await _handle_inbound(transport, executor, inbound)
                    self._status.transition(RuntimePhase.RUNNING)
                    next_delay = 0.0
                except SystemExit as error:
                    code = error.code if isinstance(error.code, int) else 1
                    if code == EXIT_UPDATE_PENDING:
                        terminal_phase = RuntimePhase.UPDATE_PENDING
                        return code
                    terminal_phase = RuntimePhase.FAILED
                    return code
                except CredentialRejected as error:
                    terminal_phase = RuntimePhase.CREDENTIAL_REJECTED
                    self._status.transition(terminal_phase, error=error)
                    return 75
                except RetryableTransportError as error:
                    self._status.record_reconnect(error)
                    next_delay = self._dependencies.reconnect_delay
                except TerminalTransportError as error:
                    terminal_phase = RuntimePhase.FAILED
                    self._status.transition(terminal_phase, error=error)
                    return 1
                except asyncio.CancelledError:
                    terminal_phase = RuntimePhase.STOPPED
                    self._status.transition(RuntimePhase.STOPPING)
                    return 0
                except GatewayIdle as idle:
                    self._status.transition(RuntimePhase.RUNNING)
                    next_delay = idle.delay
                finally:
                    await _cleanup(transport.close)

                if next_delay:
                    await self._dependencies.sleep(next_delay)
        except Exception as error:
            terminal_phase = RuntimePhase.FAILED
            self._status.transition(terminal_phase, error=error)
            return 1
        finally:
            if executor_started:
                await _cleanup(executor.stop)
            if terminal_phase is not None:
                self._status.transition(terminal_phase)


async def _cleanup(action: Callable[[], Awaitable[None]]) -> None:
    """Keep a teardown failure from replacing an already-selected exit result."""
    try:
        await action()
    except Exception:
        pass


async def _handle_inbound(
    transport: GatewayTransport,
    executor: RuntimeExecutor,
    inbound: GatewayInboundV1,
) -> None:
    """Execute only command envelopes at the current common-runtime boundary."""
    if inbound.root.kind != "command":
        raise GatewayTerminalError("unsupported Gateway inbound message")
    command = inbound.root.payload
    ack = AgentCommandAckV1(
        schema_version="agent_command_ack_v1",
        command_id=command.command_id,
        device_id=command.device_id,
        status="acknowledged",
        acknowledged_at=datetime.now(UTC),
    )
    await transport.send_ack(ack)
    result = await executor.execute(command)
    await transport.send_result(result)
