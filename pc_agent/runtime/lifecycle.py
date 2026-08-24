"""Lifecycle primitives shared by the neutral runtime application."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from endpoint_contracts import (
    AgentCommandAckV1,
    AgentCommandV1,
    AgentHeartbeatV1,
    AgentHelloV1,
    AgentResultV1,
    GatewayHelloV1,
)
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


logger = logging.getLogger(__name__)


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


def _compatibility_hello(_settings: object) -> AgentHelloV1:
    return compatibility_agent_hello()


async def _noop_after_handshake(_settings: object) -> None:
    return None


def _no_connected_tasks(
    _settings: object, _credential: str, _transport: GatewayTransport
) -> Iterable[Awaitable[None]]:
    return ()


def _no_completion_sink(_settings: object) -> Callable[[dict[str, object]], None] | None:
    return None


@dataclass(frozen=True, slots=True)
class RuntimeDependencies:
    load_credential: Callable[[object], str]
    create_executor: Callable[[], RuntimeExecutor]
    create_transport: Callable[[object, str, RuntimeExecutor], GatewayTransport]
    load_hello: Callable[[object], AgentHelloV1] = _compatibility_hello
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    heartbeat_sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    after_server_handshake: Callable[[object], Awaitable[None]] = _noop_after_handshake
    create_connected_tasks: Callable[
        [object, str, GatewayTransport], Iterable[Awaitable[None]]
    ] = _no_connected_tasks
    create_completion_sink: Callable[
        [object], Callable[[dict[str, object]], None] | None
    ] = _no_completion_sink
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
            hello = self._dependencies.load_hello(self._settings)
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
            completion_sink = self._dependencies.create_completion_sink(self._settings)
            while True:
                transport = self._dependencies.create_transport(
                    self._settings, credential, executor
                )
                next_delay: float | None = None
                try:
                    self._status.transition(RuntimePhase.CONNECTING)
                    gateway_hello = await transport.connect(hello)
                    self._status.transition(RuntimePhase.RUNNING)
                    await self._dependencies.after_server_handshake(self._settings)
                    connected_tasks = self._dependencies.create_connected_tasks(
                        self._settings, credential, transport
                    )
                    await _run_connected(
                        transport,
                        executor,
                        hello,
                        gateway_hello,
                        self._dependencies.heartbeat_sleep,
                        connected_tasks=connected_tasks,
                        completion_sink=completion_sink,
                    )
                    raise GatewayTerminalError(
                        "Gateway connected loops stopped unexpectedly"
                    )
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


async def _run_connected(
    transport: GatewayTransport,
    executor: RuntimeExecutor,
    hello: AgentHelloV1,
    gateway_hello: GatewayHelloV1,
    sleep: Callable[[float], Awaitable[None]],
    *,
    connected_tasks: Iterable[Awaitable[None]] = (),
    completion_sink: Callable[[dict[str, object]], None] | None = None,
) -> None:
    """Run receive and heartbeat loops for the lifetime of one connection."""
    tasks = {
        asyncio.create_task(_receive_loop(transport, executor, completion_sink)),
        asyncio.create_task(
            _heartbeat_loop(
                transport,
                hello,
                gateway_hello.heartbeat_interval_seconds,
                sleep,
            )
        ),
    }
    tasks.update(asyncio.ensure_future(task) for task in connected_tasks)
    try:
        done, _pending = await asyncio.wait(
            tasks,
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in done:
            if task.cancelled():
                continue
            error = task.exception()
            if error is not None:
                raise error
        raise asyncio.CancelledError()
    finally:
        for task in tasks:
            task.cancel()
        for task in tasks:
            try:
                await task
            except BaseException:
                pass


async def _receive_loop(
    transport: GatewayTransport,
    executor: RuntimeExecutor,
    completion_sink: Callable[[dict[str, object]], None] | None,
) -> None:
    while True:
        inbound = await transport.receive()
        await _handle_inbound(transport, executor, inbound, completion_sink)


async def _heartbeat_loop(
    transport: GatewayTransport,
    hello: AgentHelloV1,
    interval: float,
    sleep: Callable[[float], Awaitable[None]],
) -> None:
    platform = "linux" if hello.platform == "linux_amd64" else "windows"
    while True:
        await sleep(interval)
        await transport.send_heartbeat(
            AgentHeartbeatV1(
                schema_version="agent_heartbeat_v1",
                device_id=hello.device_id,
                platform=platform,
                agent_version=hello.agent_version,
                reported_at=datetime.now(UTC),
            )
        )


async def _handle_inbound(
    transport: GatewayTransport,
    executor: RuntimeExecutor,
    inbound: GatewayInboundV1,
    completion_sink: Callable[[dict[str, object]], None] | None = None,
) -> None:
    """Handle the bounded server-to-agent messages owned by the common runtime."""
    if inbound.root.kind == "result_ack":
        return
    if inbound.root.kind == "policy_update":
        return
    if inbound.root.kind == "command_cancel":
        return
    if inbound.root.kind == "server_shutdown_notice":
        notice = inbound.root.payload
        if notice.reason == "session_replaced":
            raise GatewayTerminalError("Gateway session was replaced")
        raise GatewayIdle(float(notice.retry_after_seconds or 0))
    if inbound.root.kind == "error":
        error = inbound.root.payload
        if error.retryable:
            raise GatewayRetryableError(error.code)
        raise GatewayTerminalError(error.code)
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
    started_at = time.monotonic()
    result = await executor.execute(command)
    emit_command_completed_marker(
        command,
        result,
        duration_ms=max(0, int((time.monotonic() - started_at) * 1000)),
        completion_sink=completion_sink,
    )
    await transport.send_result(result)


def emit_command_completed_marker(
    command: AgentCommandV1,
    result: AgentResultV1,
    *,
    duration_ms: int,
    completion_sink: Callable[[dict[str, object]], None] | None = None,
) -> None:
    """Emit the bounded local proof required for a real agent canary.

    The marker deliberately excludes command parameters and result content.  It
    is emitted before transport delivery, so a later network failure cannot
    erase the fact that the installed runtime executed the typed capability.
    """
    marker = {
        "command_id": str(command.command_id),
        "capability": command.capability,
        "status": result.status,
        "duration_ms": duration_ms,
        "result_item_count": len(result.result_items),
        "timestamp": result.completed_at.isoformat(),
    }
    logger.info(
        "endpoint_agent_command_completed",
        extra=marker,
    )
    if completion_sink is not None:
        completion_sink(marker)
