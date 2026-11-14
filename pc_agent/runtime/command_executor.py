"""Neutral typed command execution for the headless runtime."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Literal

from endpoint_contracts import AgentCommandV1, AgentResultV1
from pc_agent.context_profiles.command_execution import execute_context_agent_command
from pc_agent.context_profiles.probe import IN_OWNED_COMMAND_WORKER, SystemProbe
from pc_agent.context_profiles.registry import CONTEXT_COLLECTION_CAPABILITIES
from pc_agent.primitives.network.command_execution import execute_network_agent_command
from pc_agent.primitives.network.policy import AgentNetworkProbePolicy
from pc_agent.primitives.read_only.command_execution import execute_read_only_agent_command

from .command_worker import run_command_worker


async def _collect_context(command: AgentCommandV1, *, probe: object) -> AgentResultV1:
    return await asyncio.to_thread(execute_context_agent_command, command, probe=probe)


async def _execute_context_capability(
    executor: "CommandExecutor", command: AgentCommandV1
) -> AgentResultV1:
    return await executor._invoke_context(command)


async def _execute_network_capability(
    executor: "CommandExecutor", command: AgentCommandV1
) -> AgentResultV1:
    return await executor._invoke_network(command)


async def _execute_read_only_capability(
    executor: "CommandExecutor", command: AgentCommandV1
) -> AgentResultV1:
    return await executor._invoke_read_only(command)


BUILTIN_ENDPOINT_CAPABILITIES = {
    "context.baseline.collect": _execute_context_capability,
    "context.health.collect": _execute_context_capability,
    "context.network.collect": _execute_context_capability,
    "context.diagnostic.collect": _execute_context_capability,
    "context.session.collect": _execute_context_capability,
    "context.inventory.collect": _execute_context_capability,
    "dns.resolve": _execute_network_capability,
    "network.ping": _execute_network_capability,
    "tcp.connect": _execute_network_capability,
    "route.get": _execute_read_only_capability,
    "adapter.list": _execute_read_only_capability,
    "system.service_status": _execute_read_only_capability,
    "system.resource_snapshot": _execute_read_only_capability,
    "process.list": _execute_read_only_capability,
    "process.find": _execute_read_only_capability,
    "service.list": _execute_read_only_capability,
    "service.status": _execute_read_only_capability,
    "printer.list": _execute_read_only_capability,
    "printer.status": _execute_read_only_capability,
    "printer.queue.summary": _execute_read_only_capability,
    "software.list": _execute_read_only_capability,
    "software.find": _execute_read_only_capability,
    "filesystem.free_space": _execute_read_only_capability,
    "filesystem.path_exists": _execute_read_only_capability,
    "filesystem.file_metadata": _execute_read_only_capability,
    "eventlog.query": _execute_read_only_capability,
    "eventlog.recent_errors": _execute_read_only_capability,
}


_CAPABILITY_BUDGETS = {
    name: 45 if handler is _execute_context_capability else 12
    for name, handler in BUILTIN_ENDPOINT_CAPABILITIES.items()
}
_CAPABILITY_BUDGETS.update({"network.ping": 35, "tcp.connect": 25, "dns.resolve": 10})


def failed_result(
    command: AgentCommandV1, message: str, *, status: Literal["failed", "expired"] = "failed",
) -> AgentResultV1:
    return AgentResultV1(
        schema_version="agent_result_v1", command_id=command.command_id,
        device_id=command.device_id, status=status, message=message,
        completed_at=datetime.now(UTC),
    )


def execute_worker_command(
    command: AgentCommandV1, policy: AgentNetworkProbePolicy,
) -> AgentResultV1:
    handler = BUILTIN_ENDPOINT_CAPABILITIES.get(command.capability)
    token = IN_OWNED_COMMAND_WORKER.set(True)
    try:
        if handler is _execute_context_capability:
            return execute_context_agent_command(command, probe=SystemProbe())
        if handler is _execute_network_capability:
            return execute_network_agent_command(command, policy=policy)
        if handler is _execute_read_only_capability:
            return execute_read_only_agent_command(command, policy=policy)
        return failed_result(command, "CONTEXT_CAPABILITY_REJECTED")
    finally:
        IN_OWNED_COMMAND_WORKER.reset(token)


class CommandExecutor:
    def __init__(
        self,
        *,
        probe_factory: Callable[[], object] | None = None,
        execute_context_command: Callable[..., Any] | None = None,
        execute_network_command: Callable[..., Any] | None = None,
        execute_read_only_command: Callable[..., Any] | None = None,
        network_probe_policy: AgentNetworkProbePolicy | None = None,
    ) -> None:
        self._probe_factory = probe_factory or SystemProbe
        self._in_process_handlers = set()
        if probe_factory is not None or execute_context_command is not None:
            self._in_process_handlers.add(_execute_context_capability)
        if execute_network_command is not None:
            self._in_process_handlers.add(_execute_network_capability)
        if execute_read_only_command is not None:
            self._in_process_handlers.add(_execute_read_only_capability)
        self._execute_context_command = (
            execute_context_command or _collect_context
        )
        self._execute_network_command = (
            execute_network_command or execute_network_agent_command
        )
        self._execute_read_only_command = (
            execute_read_only_command or execute_read_only_agent_command
        )
        self._network_probe_policy = network_probe_policy or AgentNetworkProbePolicy.from_values(
            allowed_cidrs=(), allowed_suffixes=()
        )
        self._probe: object | None = None

    async def start(self) -> None:
        self._probe = self._probe_factory()

    async def stop(self) -> None:
        self._probe = None

    async def execute(self, command: AgentCommandV1) -> AgentResultV1:
        handler = BUILTIN_ENDPOINT_CAPABILITIES.get(command.capability)
        if handler is None:
            return failed_result(command, "CONTEXT_CAPABILITY_REJECTED")
        if handler not in self._in_process_handlers:
            remaining = (command.deadline_at - datetime.now(UTC)).total_seconds()
            if remaining <= 0:
                return failed_result(command, "AGENT_COMMAND_DEADLINE_EXCEEDED", status="expired")
            try:
                return await run_command_worker(
                    command, self._network_probe_policy,
                    timeout=min(remaining, _CAPABILITY_BUDGETS[command.capability]),
                )
            except TimeoutError:
                if command.deadline_at <= datetime.now(UTC):
                    return failed_result(command, "AGENT_COMMAND_DEADLINE_EXCEEDED", status="expired")
                return failed_result(command, "AGENT_COMMAND_BUDGET_EXCEEDED")
            except (OSError, ValueError):
                return failed_result(command, "AGENT_COMMAND_WORKER_FAILED")
        # These paths are explicit local dependency injection. Deployed runtimes
        # use the owned worker for every registered handler.
        result = handler(self, command)
        if inspect.isawaitable(result):
            result = await result
        if not isinstance(result, AgentResultV1):
            raise TypeError("registered endpoint capability returned an invalid result")
        return result

    async def _invoke_context(self, command: AgentCommandV1) -> AgentResultV1:
        if command.capability not in CONTEXT_COLLECTION_CAPABILITIES:
            raise ValueError("context handler received an unregistered capability")
        if self._probe is None:
            raise RuntimeError("command executor has not been started")
        result = self._execute_context_command(command, probe=self._probe)
        if inspect.isawaitable(result):
            result = await result
        if not isinstance(result, AgentResultV1):
            raise TypeError("context executor returned an invalid result")
        return result

    async def _invoke_network(self, command: AgentCommandV1) -> AgentResultV1:
        result = self._execute_network_command(
            command, policy=self._network_probe_policy
        )
        if inspect.isawaitable(result):
            result = await result
        if not isinstance(result, AgentResultV1):
            raise TypeError("network executor returned an invalid result")
        return result

    async def _invoke_read_only(self, command: AgentCommandV1) -> AgentResultV1:
        result = self._execute_read_only_command(
            command, policy=self._network_probe_policy
        )
        if inspect.isawaitable(result):
            result = await result
        if not isinstance(result, AgentResultV1):
            raise TypeError("read-only executor returned an invalid result")
        return result
