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
from endpoint_contracts.gateway_ws import EndpointPolicyAckV1, EndpointPolicyDeliveryV1
from endpoint_contracts.security_events import SecurityEventAckV1
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
_TRAY_STATUS_HEARTBEAT_SECONDS = 60.0


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


class CanaryStatusWriter(Protocol):
    """Minimal runtime boundary for redacted Windows canary transport facts."""

    def write_not_ready(self) -> None: ...
    def write_wss_ready(self) -> None: ...


class TrayStatusWriter(Protocol):
    """Bounded, local-only Windows status projection for the user tray."""

    def publish(
        self,
        *,
        agent_state: str,
        endpoint_state: str,
        update_state: str,
        reason_code: str | None = None,
    ) -> None: ...


def _compatibility_hello(_settings: object) -> AgentHelloV1:
    return compatibility_agent_hello()


async def _noop_after_handshake(_settings: object) -> None:
    return None


async def _noop_restore_policy(_settings: object) -> None:
    return None


def _no_connected_tasks(
    _settings: object, _credential: str, _transport: GatewayTransport
) -> Iterable[Awaitable[None]]:
    return ()


class LocalSensorService(Protocol):
    def stop(self) -> None: ...


def _no_local_sensor(_settings: object) -> LocalSensorService | None:
    return None


def _no_completion_sink(_settings: object) -> Callable[[dict[str, object]], None] | None:
    return None


def _no_canary_status_writer(_settings: object) -> CanaryStatusWriter | None:
    return None


def _no_tray_status_writer(_settings: object) -> TrayStatusWriter | None:
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
    restore_policy: Callable[[object], Awaitable[object]] = _noop_restore_policy
    start_local_sensor: Callable[[object], LocalSensorService | None] = _no_local_sensor
    policy_handler: Callable[[EndpointPolicyDeliveryV1], Awaitable[EndpointPolicyAckV1]] | None = None
    security_ack_handler: Callable[[SecurityEventAckV1], Awaitable[bool]] | None = None
    create_connected_tasks: Callable[
        [object, str, GatewayTransport], Iterable[Awaitable[None]]
    ] = _no_connected_tasks
    create_completion_sink: Callable[
        [object], Callable[[dict[str, object]], None] | None
    ] = _no_completion_sink
    create_canary_status_writer: Callable[[object], CanaryStatusWriter | None] = (
        _no_canary_status_writer
    )
    create_tray_status_writer: Callable[[object], TrayStatusWriter | None] = (
        _no_tray_status_writer
    )
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
        local_sensor: LocalSensorService | None = None
        terminal_phase: RuntimePhase | None = None
        tray_status_writer: TrayStatusWriter | None = None
        try:
            await executor.start()
            executor_started = True
            await self._dependencies.restore_policy(self._settings)
            local_sensor = self._dependencies.start_local_sensor(self._settings)
            completion_sink = self._dependencies.create_completion_sink(self._settings)
            canary_status_writer = self._dependencies.create_canary_status_writer(
                self._settings
            )
            try:
                tray_status_writer = self._dependencies.create_tray_status_writer(
                    self._settings
                )
            except Exception:
                tray_status_writer = None
            _publish_tray_status(
                tray_status_writer,
                agent_state="starting",
                endpoint_state="connecting",
                update_state="unknown",
            )
            while True:
                transport = self._dependencies.create_transport(
                    self._settings, credential, executor
                )
                next_delay: float | None = None
                try:
                    if canary_status_writer is not None:
                        canary_status_writer.write_not_ready()
                    self._status.transition(RuntimePhase.CONNECTING)
                    gateway_hello = await transport.connect(hello)
                    self._status.transition(RuntimePhase.RUNNING)
                    if canary_status_writer is not None:
                        canary_status_writer.write_wss_ready()
                    _publish_tray_status(
                        tray_status_writer,
                        agent_state="running",
                        endpoint_state="connected",
                        update_state="up_to_date",
                    )
                    await self._dependencies.after_server_handshake(self._settings)
                    connected_tasks = self._dependencies.create_connected_tasks(
                        self._settings, credential, transport
                    )
                    if tray_status_writer is not None:
                        connected_tasks = (
                            *connected_tasks,
                            _tray_status_heartbeat(
                                tray_status_writer,
                                self._dependencies.heartbeat_sleep,
                            ),
                        )
                    await _run_connected(
                        transport,
                        executor,
                        hello,
                        gateway_hello,
                        self._dependencies.heartbeat_sleep,
                        connected_tasks=connected_tasks,
                        completion_sink=completion_sink,
                        policy_handler=self._dependencies.policy_handler,
                        security_ack_handler=self._dependencies.security_ack_handler,
                    )
                    raise GatewayTerminalError(
                        "Gateway connected loops stopped unexpectedly"
                    )
                except SystemExit as error:
                    code = error.code if isinstance(error.code, int) else 1
                    if code == EXIT_UPDATE_PENDING:
                        terminal_phase = RuntimePhase.UPDATE_PENDING
                        _publish_tray_status(
                            tray_status_writer,
                            agent_state="running",
                            endpoint_state="connected",
                            update_state="pending",
                        )
                        return code
                    terminal_phase = RuntimePhase.FAILED
                    _publish_tray_status(
                        tray_status_writer,
                        agent_state="error",
                        endpoint_state="unknown",
                        update_state="unknown",
                        reason_code="RUNTIME_EXIT",
                    )
                    return code
                except CredentialRejected as error:
                    terminal_phase = RuntimePhase.CREDENTIAL_REJECTED
                    self._status.transition(terminal_phase, error=error)
                    _publish_tray_status(
                        tray_status_writer,
                        agent_state="error",
                        endpoint_state="unknown",
                        update_state="unknown",
                        reason_code="CREDENTIAL_REJECTED",
                    )
                    return 75
                except RetryableTransportError as error:
                    if canary_status_writer is not None:
                        canary_status_writer.write_not_ready()
                    self._status.record_reconnect(error)
                    _publish_tray_status(
                        tray_status_writer,
                        agent_state="running",
                        endpoint_state="disconnected",
                        update_state="up_to_date",
                    )
                    next_delay = self._dependencies.reconnect_delay
                except TerminalTransportError as error:
                    terminal_phase = RuntimePhase.FAILED
                    self._status.transition(terminal_phase, error=error)
                    _publish_tray_status(
                        tray_status_writer,
                        agent_state="error",
                        endpoint_state="unknown",
                        update_state="unknown",
                        reason_code="TRANSPORT_TERMINAL",
                    )
                    return 1
                except asyncio.CancelledError:
                    terminal_phase = RuntimePhase.STOPPED
                    self._status.transition(RuntimePhase.STOPPING)
                    _publish_tray_status(
                        tray_status_writer,
                        agent_state="stopped",
                        endpoint_state="unknown",
                        update_state="up_to_date",
                    )
                    return 0
                except GatewayIdle as idle:
                    if canary_status_writer is not None:
                        canary_status_writer.write_not_ready()
                    self._status.transition(RuntimePhase.RUNNING)
                    next_delay = idle.delay
                finally:
                    await _cleanup(transport.close)

                if next_delay:
                    await self._dependencies.sleep(next_delay)
        except Exception as error:
            terminal_phase = RuntimePhase.FAILED
            self._status.transition(terminal_phase, error=error)
            _publish_tray_status(
                tray_status_writer,
                agent_state="error",
                endpoint_state="unknown",
                update_state="unknown",
                reason_code="RUNTIME_FAILURE",
            )
            return 1
        finally:
            if local_sensor is not None:
                await _cleanup(lambda: asyncio.to_thread(local_sensor.stop))
            if executor_started:
                await _cleanup(executor.stop)
            if terminal_phase is not None:
                self._status.transition(terminal_phase)


def _publish_tray_status(
    writer: TrayStatusWriter | None,
    *,
    agent_state: str,
    endpoint_state: str,
    update_state: str,
    reason_code: str | None = None,
) -> None:
    """A user-facing projection must never affect the headless agent lifecycle."""
    if writer is None:
        return
    try:
        writer.publish(
            agent_state=agent_state,
            endpoint_state=endpoint_state,
            update_state=update_state,
            reason_code=reason_code,
        )
    except Exception:
        logger.warning("could not publish Windows tray status", exc_info=True)


async def _tray_status_heartbeat(
    writer: TrayStatusWriter,
    sleep: Callable[[float], Awaitable[None]],
) -> None:
    """Keep a healthy, quiet WSS session visible to the local tray."""
    while True:
        await sleep(_TRAY_STATUS_HEARTBEAT_SECONDS)
        _publish_tray_status(
            writer,
            agent_state="running",
            endpoint_state="connected",
            update_state="up_to_date",
        )


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
    policy_handler: Callable[[EndpointPolicyDeliveryV1], Awaitable[EndpointPolicyAckV1]] | None = None,
    security_ack_handler: Callable[[SecurityEventAckV1], Awaitable[bool]] | None = None,
) -> None:
    """Run receive and heartbeat loops for the lifetime of one connection."""
    tasks = {
        asyncio.create_task(_receive_loop(
            transport, executor, completion_sink, policy_handler, security_ack_handler,
        )),
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
    policy_handler: Callable[[EndpointPolicyDeliveryV1], Awaitable[EndpointPolicyAckV1]] | None,
    security_ack_handler: Callable[[SecurityEventAckV1], Awaitable[bool]] | None,
) -> None:
    while True:
        inbound = await transport.receive()
        await _handle_inbound(
            transport, executor, inbound, completion_sink,
            policy_handler=policy_handler,
            security_ack_handler=security_ack_handler,
        )


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
    *,
    policy_handler: Callable[[EndpointPolicyDeliveryV1], Awaitable[EndpointPolicyAckV1]] | None = None,
    security_ack_handler: Callable[[SecurityEventAckV1], Awaitable[bool]] | None = None,
) -> None:
    """Handle the bounded server-to-agent messages owned by the common runtime."""
    if inbound.root.kind == "result_ack":
        return
    if inbound.root.kind == "policy_update":
        return
    if inbound.root.kind == "endpoint_policy_delivery":
        send_ack = getattr(transport, "send_policy_ack", None)
        if policy_handler is None or not callable(send_ack):
            raise GatewayTerminalError("Endpoint Policy runtime is unavailable")
        ack = await policy_handler(inbound.root.payload)
        await send_ack(ack)
        return
    if inbound.root.kind == "security_event_ack":
        if security_ack_handler is None:
            raise GatewayTerminalError("SecurityEvent ACK runtime is unavailable")
        await security_ack_handler(inbound.root.payload)
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
        try:
            completion_sink(marker)
        except Exception:
            logger.warning("endpoint_agent_completion_sink_failed")
