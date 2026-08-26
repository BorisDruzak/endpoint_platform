"""Neutral typed command execution for the headless runtime."""

from __future__ import annotations

import inspect
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from endpoint_contracts import AgentCommandV1, AgentResultV1
from pc_agent.context_profiles.command_execution import execute_context_agent_command
from pc_agent.context_profiles.probe import SystemProbe
from pc_agent.context_profiles.registry import CONTEXT_COLLECTION_CAPABILITIES
from pc_agent.primitives.network.command_execution import execute_network_agent_command
from pc_agent.primitives.network.policy import AgentNetworkProbePolicy


async def _execute_context_capability(
    executor: "CommandExecutor", command: AgentCommandV1
) -> AgentResultV1:
    return await executor._invoke_context(command)


async def _execute_network_capability(
    executor: "CommandExecutor", command: AgentCommandV1
) -> AgentResultV1:
    return await executor._invoke_network(command)


BUILTIN_ENDPOINT_CAPABILITIES = {
    "context.baseline.collect": _execute_context_capability,
    "context.health.collect": _execute_context_capability,
    "context.network.collect": _execute_context_capability,
    "context.diagnostic.collect": _execute_context_capability,
    "dns.resolve": _execute_network_capability,
    "network.ping": _execute_network_capability,
    "tcp.connect": _execute_network_capability,
}


class CommandExecutor:
    def __init__(
        self,
        *,
        probe_factory: Callable[[], object] | None = None,
        execute_context_command: Callable[..., Any] | None = None,
        execute_network_command: Callable[..., Any] | None = None,
        network_probe_policy: AgentNetworkProbePolicy | None = None,
    ) -> None:
        self._probe_factory = probe_factory or SystemProbe
        self._execute_context_command = (
            execute_context_command or execute_context_agent_command
        )
        self._execute_network_command = (
            execute_network_command or execute_network_agent_command
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
            return AgentResultV1(
                schema_version="agent_result_v1",
                command_id=command.command_id,
                device_id=command.device_id,
                status="failed",
                result_items=[],
                message="CONTEXT_CAPABILITY_REJECTED",
                completed_at=datetime.now(UTC),
            )
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
