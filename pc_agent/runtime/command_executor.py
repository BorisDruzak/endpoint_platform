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


class CommandExecutor:
    def __init__(
        self,
        *,
        probe_factory: Callable[[], object] | None = None,
        execute_context_command: Callable[..., Any] | None = None,
    ) -> None:
        self._probe_factory = probe_factory or SystemProbe
        self._execute_context_command = (
            execute_context_command or execute_context_agent_command
        )
        self._probe: object | None = None

    async def start(self) -> None:
        self._probe = self._probe_factory()

    async def stop(self) -> None:
        self._probe = None

    async def execute(self, command: AgentCommandV1) -> AgentResultV1:
        if command.capability not in CONTEXT_COLLECTION_CAPABILITIES:
            return AgentResultV1(
                schema_version="agent_result_v1",
                command_id=command.command_id,
                device_id=command.device_id,
                status="failed",
                result_items=[],
                message="CONTEXT_CAPABILITY_REJECTED",
                completed_at=datetime.now(UTC),
            )
        if self._probe is None:
            raise RuntimeError("command executor has not been started")
        result = self._execute_context_command(command, probe=self._probe)
        if inspect.isawaitable(result):
            result = await result
        if not isinstance(result, AgentResultV1):
            raise TypeError("context executor returned an invalid result")
        return result
