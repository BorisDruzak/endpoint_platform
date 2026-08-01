"""Lifecycle primitives shared by the neutral runtime application."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol

from pc_agent.version import EXIT_UPDATE_PENDING

from .status import RuntimePhase, RuntimeStatus


class CredentialRejected(RuntimeError):
    """A durable Endpoint credential was rejected and must not retry in-process."""


class RetryableTransportError(RuntimeError):
    """A transient Endpoint transport failure that permits reconnect."""


class TerminalTransportError(RuntimeError):
    """A transport/configuration failure that must end the process."""


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


class RuntimeTransport(Protocol):
    async def start(self) -> ContinueAfter | None: ...
    async def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class RuntimeDependencies:
    load_credential: Callable[[object], str]
    create_executor: Callable[[], RuntimeExecutor]
    create_transport: Callable[[object, str, RuntimeExecutor], RuntimeTransport]
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
                    outcome = await transport.start()
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
                else:
                    if outcome is None:
                        terminal_phase = RuntimePhase.STOPPED
                        self._status.transition(RuntimePhase.STOPPING)
                        return 0
                    if not isinstance(outcome, ContinueAfter):
                        terminal_phase = RuntimePhase.FAILED
                        self._status.transition(
                            terminal_phase,
                            error=TypeError("invalid transport attempt outcome"),
                        )
                        return 1
                    self._status.transition(RuntimePhase.RUNNING)
                    next_delay = outcome.delay
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
